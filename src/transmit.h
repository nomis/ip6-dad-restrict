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
#ifndef IP6_DAD_RESTRICT_TRANSMIT_H_
#define IP6_DAD_RESTRICT_TRANSMIT_H_

#include <netpacket/packet.h>
#include <array>
#include <string>
#include <vector>

#include "capture.h"
#include "common.h"

namespace ip6_dad_restrict {

class Transmit {
public:
	Transmit(const std::string &interface);
	~Transmit() ;

	Transmit(const Transmit&) = delete;
	Transmit& operator=(const Transmit&) = delete;

	static std::array<unsigned char,2> icmp6_checksum(const std::array<unsigned char,IP6_ADDR_LEN> &source_ip,
			const std::array<unsigned char,IP6_ADDR_LEN> &dest_ip,
			const std::vector<unsigned char> &data);

	explicit operator bool() const { return fd_ != -1; }

	std::array<unsigned char,6> interface_mac() const { return interface_mac_; };

	void transmit_ndp_na(const std::array<unsigned char,ETH_MAC_LEN> &dest_mac,
			const std::array<unsigned char,IP6_ADDR_LEN> &source_ip, const std::array<unsigned char,IP6_ADDR_LEN> &dest_ip,
			const std::array<unsigned char,IP6_ADDR_LEN> &target_ip, bool router, bool solicited, bool override,
			bool opt_target_mac, const std::array<unsigned char,ETH_MAC_LEN> &target_mac);
	void transmit_ndp_na_block_dad(const std::array<unsigned char,IP6_ADDR_LEN> &target_ip);
	void transmit_ndp_na_block_dad(const DADPacket &packet);

private:
	void transmit_eth(const std::array<unsigned char,ETH_MAC_LEN> &dest_mac,
			const std::array<unsigned char,ETH_PROTO_LEN> &protocol, const std::vector<unsigned char> &data);
	void transmit_ip6(const std::array<unsigned char,ETH_MAC_LEN> &dest_mac,
			const std::array<unsigned char,IP6_ADDR_LEN> &source_ip, const std::array<unsigned char,IP6_ADDR_LEN> &dest_ip,
			unsigned char protocol, const std::vector<unsigned char> &data);

	int fd_;
	struct sockaddr_ll sll_;
	std::array<unsigned char,ETH_MAC_LEN> interface_mac_;
};

} // namespace ip6_dad_restrict

#endif
