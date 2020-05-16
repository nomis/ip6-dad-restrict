/*
	ip6-dad-restrict
	Copyright 2020  Simon Arlott

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
#include "transmit.h"

#include <netpacket/packet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <string.h>
#include <unistd.h>
#include <array>
#include <chrono>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <boost/format.hpp>

#include "capture.h"
#include "common.h"
#include "print_error.h"

using ::boost::format;
using ::std::array;
using ::std::chrono::duration_cast;
using ::std::chrono::microseconds;
using ::std::chrono::seconds;
using ::std::chrono::system_clock;
using ::std::copy;
using ::std::cout;
using ::std::endl;
using ::std::string;
using ::std::unique_ptr;
using ::std::vector;

namespace ip6_dad_restrict {

Transmit::Transmit(const std::string &interface) {
	fd_ = ::socket(AF_PACKET, SOCK_RAW, 0);

	if (fd_ == -1) {
		print_system_error(format("socket: %1%"));
		return;
	}

	struct ifaddrs *ifa = nullptr;

	if (::getifaddrs(&ifa) != 0) {
		print_system_error(format("getifaddrs: %1%"));
		return;
	}

	struct ifaddrs *ifp = ifa;

	while (ifp != NULL) {
		if (ifp->ifa_addr->sa_family == AF_PACKET && ifp->ifa_addr != nullptr && string(ifp->ifa_name) == interface) {
			const struct sockaddr_ll *sll = (const struct sockaddr_ll *)ifp->ifa_addr;

			if (sll->sll_halen == ETH_MAC_LEN) {
				sll_ = *sll;
				sll_.sll_protocol = 0;
				sll_.sll_hatype = 0;
				sll_.sll_pkttype = 0;
				copy(&sll->sll_addr[0], &sll->sll_addr[ETH_MAC_LEN], &interface_mac_[0]);
			}
			break;
		}
		ifp = ifp->ifa_next;
	}

	::freeifaddrs(ifa);
}

Transmit::~Transmit() {
	if (fd_ != -1) {
		::close(fd_);
	}
}

array<unsigned char,2> Transmit::icmp6_checksum(const array<unsigned char,IP6_ADDR_LEN> &source_ip,
		const array<unsigned char,IP6_ADDR_LEN> &dest_ip,
		const vector<unsigned char> &data) {
	unsigned int checksum = 0;

	for (size_t i = 0; i < IP6_ADDR_LEN; i += 2) {
		checksum += source_ip[i] << 8 | source_ip[i + 1];
	}

	for (size_t i = 0; i < IP6_ADDR_LEN; i += 2) {
		checksum += dest_ip[i] << 8 | dest_ip[i + 1];
	}

	checksum += (data.size() >> 16) & 0xFFFF;
	checksum += data.size() & 0xFFFF;
	checksum += PROTO_ICMP6; // Next header

	for (size_t i = 0; i < data.size(); i += 2) {
		checksum += data[i] << 8 | data[i + 1];
	}

	checksum = (checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF);
	checksum = (checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF);
	checksum = checksum ^ 0xFFFF;

	return array<unsigned char,2>{ (unsigned char)((checksum >> 8) & 0xFF), (unsigned char)(checksum & 0xFF) };
}

void Transmit::transmit_eth(const std::array<unsigned char,ETH_MAC_LEN> &dest_mac,
		const std::array<unsigned char,ETH_PROTO_LEN> &protocol, const std::vector<unsigned char> &data) {
	struct sockaddr_ll sll = sll_;
	vector<unsigned char> packet(ETH_HDR_LEN + data.size());

	::memcpy(packet.data(), &sll, sizeof(sll));
	copy(&dest_mac[0], &dest_mac[ETH_MAC_LEN], &packet[0]); // MAC Destination
	copy(&interface_mac_[0], &interface_mac_[ETH_MAC_LEN], &packet[6]); // MAC Source
	copy(&protocol[0], &protocol[ETH_PROTO_LEN], &packet[12]); // Ethertype
	copy(data.begin(), data.end(), &packet[14]); // Payload

	auto now = system_clock::now().time_since_epoch();
	if (fd_) {
		int ret = ::sendto(fd_, packet.data(), packet.size(), MSG_DONTROUTE, (const struct sockaddr *)&sll, sizeof(sll));
		if (ret == -1 || (size_t)ret != packet.size()) {
			print_system_error(format("sendto: %1%"));
		}
	}

	cout << format("%1%.%2$06d Out") % duration_cast<seconds>(now).count() % (duration_cast<microseconds>(now) - duration_cast<microseconds>(duration_cast<seconds>(now))).count();
	cout << format(" %1$02x:%2$02x:%3$02x:%4$02x:%5$02x:%6$02x") % (int)interface_mac_[0] % (int)interface_mac_[1] % (int)interface_mac_[2] % (int)interface_mac_[3] % (int)interface_mac_[4] % (int)interface_mac_[51];
	cout << format(" > %1$02x:%2$02x:%3$02x:%4$02x:%5$02x:%6$02x") % (int)dest_mac[0] % (int)dest_mac[1] % (int)dest_mac[2] % (int)dest_mac[3] % (int)dest_mac[4] % (int)dest_mac[5];
}

void Transmit::transmit_ip6(const std::array<unsigned char,ETH_MAC_LEN> &dest_mac,
		const std::array<unsigned char,IP6_ADDR_LEN> &source_ip, const std::array<unsigned char,IP6_ADDR_LEN> &dest_ip,
		unsigned char protocol, const std::vector<unsigned char> &data) {
	vector<unsigned char> packet(IP6_HDR_LEN + data.size());

	packet[0] = 0x60; // Version, Traffic Class
	packet[1] = 0; // Traffic Class, Flow Label
	packet[2] = 0; // Flow Label
	packet[3] = 0; // Flow Label
	packet[4] = data.size() >> 8; // Length
	packet[5] = data.size(); // Length
	packet[6] = protocol; // Next Header
	packet[7] = MAX_TTL; // Hop Limit
	copy(&source_ip[0], &source_ip[IP6_ADDR_LEN], &packet[8]); // Source Address
	copy(&dest_ip[0], &dest_ip[IP6_ADDR_LEN], &packet[24]); // Destination Address
	copy(data.begin(), data.end(), &packet[40]); // Payload

	transmit_eth(dest_mac, array<unsigned char,ETH_PROTO_LEN>{ 0x86, 0xDD }, packet);

	cout << format(", %1$02x%2$02x:%3$02x%4$02x:%5$02x%6$02x:%7$02x%8$02x:%9$02x%10$02x:%11$02x%12$02x:%13$02x%14$02x:%15$02x%16$02x")
					% (int)packet[8+ 0] % (int)packet[8+ 1] % (int)packet[8+ 2] % (int)packet[8+ 3]
					% (int)packet[8+ 4] % (int)packet[8+ 5] % (int)packet[8+ 6] % (int)packet[8+ 7]
					% (int)packet[8+ 8] % (int)packet[8+ 9] % (int)packet[8+10] % (int)packet[8+11]
					% (int)packet[8+12] % (int)packet[8+13] % (int)packet[8+14] % (int)packet[8+15];
	cout << format(" > %1$02x%2$02x:%3$02x%4$02x:%5$02x%6$02x:%7$02x%8$02x:%9$02x%10$02x:%11$02x%12$02x:%13$02x%14$02x:%15$02x%16$02x")
					% (int)packet[8+16] % (int)packet[8+17] % (int)packet[8+18] % (int)packet[8+19]
					% (int)packet[8+20] % (int)packet[8+21] % (int)packet[8+22] % (int)packet[8+23]
					% (int)packet[8+24] % (int)packet[8+25] % (int)packet[8+26] % (int)packet[8+27]
					% (int)packet[8+28] % (int)packet[8+29] % (int)packet[8+30] % (int)packet[8+31];
	cout << format(" TTL %1$d") % (int)packet[7];
}

void Transmit::transmit_ndp_na(const array<unsigned char,ETH_MAC_LEN> &dest_mac,
		const array<unsigned char,IP6_ADDR_LEN> &source_ip, const array<unsigned char,IP6_ADDR_LEN> &dest_ip,
		const array<unsigned char,IP6_ADDR_LEN> &target_ip, bool router, bool solicited, bool override,
		bool opt_target_mac, const array<unsigned char,ETH_MAC_LEN> &target_mac) {
	vector<unsigned char> packet(NDP_LEN + (opt_target_mac ? 8 : 0));

	packet[0] = 136; // ICMP Type
	packet[1] = 0; // ICMP Code
	packet[2] = 0; // Checksum
	packet[3] = 0; // Checksum
	packet[4] = (router ? 0x80 : 0x00) | (solicited ? 0x40 : 0x00) | (override ? 0x20 : 0x00); // Flags
	packet[5] = 0; // Reserved
	packet[6] = 0; // Reserved
	packet[7] = 0; // Reserved

	copy(&target_ip[0], &target_ip[IP6_ADDR_LEN], &packet[8]); // Target Address

	if (opt_target_mac) { // Option
		packet[24] = 2; // Type
		packet[25] = 1; // Length
		copy(&target_mac[0], &target_mac[ETH_MAC_LEN], &packet[26]); // Link-Layer Address
	}

	const auto checksum = icmp6_checksum(source_ip, dest_ip, packet);
	copy(&checksum[0], &checksum[2], &packet[2]);

	transmit_ip6(dest_mac, source_ip, dest_ip, PROTO_ICMP6, packet);

	cout << format(", NA %1$02x%2$02x:%3$02x%4$02x:%5$02x%6$02x:%7$02x%8$02x:%9$02x%10$02x:%11$02x%12$02x:%13$02x%14$02x:%15$02x%16$02x")
					% (int)packet[8+ 0] % (int)packet[8+ 1] % (int)packet[8+ 2] % (int)packet[8+ 3]
					% (int)packet[8+ 4] % (int)packet[8+ 5] % (int)packet[8+ 6] % (int)packet[8+ 7]
					% (int)packet[8+ 8] % (int)packet[8+ 9] % (int)packet[8+10] % (int)packet[8+11]
					% (int)packet[8+12] % (int)packet[8+13] % (int)packet[8+14] % (int)packet[8+15];
	cout << endl;
}

void Transmit::transmit_ndp_na_block_dad(const array<unsigned char,IP6_ADDR_LEN> &target_ip) {
	transmit_ndp_na(array<unsigned char,ETH_MAC_LEN>{
				0x33, 0x33, 0x00, 0x00, 0x00, 0x01
			}, target_ip,
			array<unsigned char,IP6_ADDR_LEN>{
				0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
			}, target_ip, false, false, true,
			true, interface_mac_);
}

void Transmit::transmit_ndp_na_block_dad(const DADPacket &packet) {
	transmit_ndp_na_block_dad(packet.target_ip);
}

} // namespace ip6_dad_restrict
