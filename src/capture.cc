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
#include "capture.h"

#include <string.h>
#include <pcap/pcap.h>
#include <array>
#include <iostream>
#include <memory>
#include <string>

#include <boost/format.hpp>

#include "print_error.h"

using ::boost::format;
using ::std::array;
using ::std::cout;
using ::std::endl;
using ::std::make_unique;
using ::std::shared_ptr;
using ::std::string;
using ::std::unique_ptr;

namespace ip6_dad_restrict {

Capture::Capture(const std::string &interface) {
	char errbuf[PCAP_ERRBUF_SIZE] = { 0 };

	handle_ = shared_ptr<pcap>(::pcap_open_live(interface.c_str(), 2*1024*1024, 1, 0, errbuf),
			[] (pcap_t *p) { if (p != nullptr) { ::pcap_close(p); } });

	if (!string(errbuf).empty()) {
		print_system_error(format("pcap: %1%"), errbuf);
	}

	struct bpf_program fp;

	if (::pcap_compile(handle_.get(), &fp, "icmp6 and ip6[40] = 135 and ip6[41] = 0", 1, PCAP_NETMASK_UNKNOWN) != 0) {
		print_system_error(format("pcap: %1%"), ::pcap_geterr(handle_.get()));
		handle_.reset();
		return;
	}

	if (::pcap_setfilter(handle_.get(), &fp) != 0) {
		print_system_error(format("pcap: %1%"), ::pcap_geterr(handle_.get()));
		handle_.reset();
		return;
	}
}

std::unique_ptr<DADPacket> Capture::next() {
	if (!handle_) {
		return nullptr;
	}

	constexpr size_t ETH_HDR_LEN = 14;
	constexpr size_t ETH_MIN_LEN = ETH_HDR_LEN;
	constexpr size_t IP6_HDR_LEN = 40;
	constexpr size_t IP6_MIN_LEN = ETH_HDR_LEN + IP6_HDR_LEN;
	constexpr size_t NDP_LEN = 24;
	constexpr size_t NDP_MIN_LEN = IP6_MIN_LEN + NDP_LEN;
	constexpr size_t MAXTTL = 255;
	struct pcap_pkthdr *header;
	const u_char *data;

	int ret = ::pcap_next_ex(handle_.get(), &header, &data);
	if (ret != 1) {
		if (ret == -1) {
			print_system_error(format("pcap: %1%"), ::pcap_geterr(handle_.get()));
		}
		handle_.reset();
		return nullptr;
	}

	unique_ptr<DADPacket> packet;
	cout << format("%1%.%2$06d") % header->ts.tv_sec % header->ts.tv_usec;

	if (header->caplen >= ETH_MIN_LEN) {
		cout << format(" %1$02x:%2$02x:%3$02x:%4$02x:%5$02x:%6$02x") % (int)data[6] % (int)data[7] % (int)data[8] % (int)data[9] % (int)data[10] % (int)data[11];
		cout << format(" > %1$02x:%2$02x:%3$02x:%4$02x:%5$02x:%6$02x") % (int)data[0] % (int)data[1] % (int)data[2] % (int)data[3] % (int)data[4] % (int)data[5];
	}

	if (header->caplen >= IP6_MIN_LEN) {
		cout << format(", %1$02x%2$02x:%3$02x%4$02x:%5$02x%6$02x:%7$02x%8$02x:%9$02x%10$02x:%11$02x%12$02x:%13$02x%14$02x:%15$02x%16$02x")
						% (int)data[ETH_MIN_LEN+8+ 0] % (int)data[ETH_MIN_LEN+8+ 1] % (int)data[ETH_MIN_LEN+8+ 2] % (int)data[ETH_MIN_LEN+8+ 3]
						% (int)data[ETH_MIN_LEN+8+ 4] % (int)data[ETH_MIN_LEN+8+ 5] % (int)data[ETH_MIN_LEN+8+ 6] % (int)data[ETH_MIN_LEN+8+ 7]
						% (int)data[ETH_MIN_LEN+8+ 8] % (int)data[ETH_MIN_LEN+8+ 9] % (int)data[ETH_MIN_LEN+8+10] % (int)data[ETH_MIN_LEN+8+11]
						% (int)data[ETH_MIN_LEN+8+12] % (int)data[ETH_MIN_LEN+8+13] % (int)data[ETH_MIN_LEN+8+14] % (int)data[ETH_MIN_LEN+8+15];
		cout << format(" > %1$02x%2$02x:%3$02x%4$02x:%5$02x%6$02x:%7$02x%8$02x:%9$02x%10$02x:%11$02x%12$02x:%13$02x%14$02x:%15$02x%16$02x")
						% (int)data[ETH_MIN_LEN+8+16] % (int)data[ETH_MIN_LEN+8+17] % (int)data[ETH_MIN_LEN+8+18] % (int)data[ETH_MIN_LEN+8+19]
						% (int)data[ETH_MIN_LEN+8+20] % (int)data[ETH_MIN_LEN+8+21] % (int)data[ETH_MIN_LEN+8+22] % (int)data[ETH_MIN_LEN+8+23]
						% (int)data[ETH_MIN_LEN+8+24] % (int)data[ETH_MIN_LEN+8+25] % (int)data[ETH_MIN_LEN+8+26] % (int)data[ETH_MIN_LEN+8+27]
						% (int)data[ETH_MIN_LEN+8+28] % (int)data[ETH_MIN_LEN+8+29] % (int)data[ETH_MIN_LEN+8+30] % (int)data[ETH_MIN_LEN+8+31];
		cout << format(" TTL %1$d") % (int)data[ETH_HDR_LEN+7];
	}

	if (header->caplen >= IP6_MIN_LEN && data[ETH_HDR_LEN+7] == MAXTTL && header->caplen >= NDP_MIN_LEN) {
		cout << format(", NS %1$02x%2$02x:%3$02x%4$02x:%5$02x%6$02x:%7$02x%8$02x:%9$02x%10$02x:%11$02x%12$02x:%13$02x%14$02x:%15$02x%16$02x")
						% (int)data[IP6_MIN_LEN+8+ 0] % (int)data[IP6_MIN_LEN+8+ 1] % (int)data[IP6_MIN_LEN+8+ 2] % (int)data[IP6_MIN_LEN+8+ 3]
						% (int)data[IP6_MIN_LEN+8+ 4] % (int)data[IP6_MIN_LEN+8+ 5] % (int)data[IP6_MIN_LEN+8+ 6] % (int)data[IP6_MIN_LEN+8+ 7]
						% (int)data[IP6_MIN_LEN+8+ 8] % (int)data[IP6_MIN_LEN+8+ 9] % (int)data[IP6_MIN_LEN+8+10] % (int)data[IP6_MIN_LEN+8+11]
						% (int)data[IP6_MIN_LEN+8+12] % (int)data[IP6_MIN_LEN+8+13] % (int)data[IP6_MIN_LEN+8+14] % (int)data[IP6_MIN_LEN+8+15];

		const char zero[16] = { 0 };
		if (!::memcmp(&data[ETH_HDR_LEN+8], zero, sizeof(zero))) {
			cout << " DAD";

			packet = make_unique<DADPacket>(
							array<unsigned char,6>{ data[6], data[7], data[8], data[9], data[10], data[11] },
							array<unsigned char,16>{
								data[IP6_MIN_LEN+8+ 0], data[IP6_MIN_LEN+8+ 1], data[IP6_MIN_LEN+8+ 2], data[IP6_MIN_LEN+8+ 3],
								data[IP6_MIN_LEN+8+ 4], data[IP6_MIN_LEN+8+ 5], data[IP6_MIN_LEN+8+ 6], data[IP6_MIN_LEN+8+ 7],
								data[IP6_MIN_LEN+8+ 8], data[IP6_MIN_LEN+8+ 9], data[IP6_MIN_LEN+8+10], data[IP6_MIN_LEN+8+11],
								data[IP6_MIN_LEN+8+12], data[IP6_MIN_LEN+8+13], data[IP6_MIN_LEN+8+14], data[IP6_MIN_LEN+8+15]
							}
						);

			switch (packet->type()) {
			case AddressType::GLOBAL_UNICAST:
				cout << " GU";

				if (packet->eui64()) {
					cout << " EUI-64";
				}
				break;

			case AddressType::UNIQUE_LOCAL_UNICAST:
				cout << " ULA";

				if (packet->eui64()) {
					cout << " EUI-64";
				}
				break;

			case AddressType::LINK_SCOPED_UNICAST:
				cout << " LL";

				if (packet->eui64()) {
					cout << " EUI-64";
				}
				break;

			case AddressType::MULTICAST:
				cout << " MC";
				break;

			case AddressType::UNKNOWN:
				break;
			}
		}
	}

	cout << endl;
	return packet;
}

bool DADPacket::eui64() const {
	return target_ip[8] == (source_mac[0] ^ 0x02) &&
		target_ip[9] == source_mac[1] &&
		target_ip[10] == source_mac[2] &&
		target_ip[11] == 0xFF &&
		target_ip[12] == 0xFE &&
		target_ip[13] == source_mac[3] &&
		target_ip[14] == source_mac[4] &&
		target_ip[15] == source_mac[5];
}

AddressType DADPacket::type() const {
	if ((target_ip[0] & 0xE0) == 0x20) { // Global Unicast (2000::/3)
		return AddressType::GLOBAL_UNICAST;
	} else if ((target_ip[0] & 0xFE) == 0xFC) { // Unique Local Unicast (fc00::/7)
		return AddressType::UNIQUE_LOCAL_UNICAST;
	} else if (target_ip[0] == 0xFE && (target_ip[1] & 0xC0) == 0x80) { // Link-Scoped Unicast (fe80::/10)
		return AddressType::LINK_SCOPED_UNICAST;
	} else if (target_ip[0] == 0xFF) { // Multicast (ff00::/8)
		return AddressType::MULTICAST;
	} else {
		return AddressType::UNKNOWN;
	}
}

bool DADPacket::bad() const {
	return (type() == AddressType::GLOBAL_UNICAST || type() == AddressType::UNIQUE_LOCAL_UNICAST) && !eui64();
}

} // namespace ip6_dad_restrict
