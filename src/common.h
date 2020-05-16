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
#ifndef IP6_DAD_RESTRICT_COMMON_H_
#define IP6_DAD_RESTRICT_COMMON_H_

namespace ip6_dad_restrict {

constexpr size_t ETH_MAC_LEN = 6;
constexpr size_t ETH_PROTO_LEN = 2;
constexpr size_t ETH_HDR_LEN = ETH_MAC_LEN + ETH_MAC_LEN + ETH_PROTO_LEN;
constexpr size_t ETH_MIN_LEN = ETH_HDR_LEN;

constexpr size_t IP6_ADDR_LEN = 16;
constexpr size_t IP6_HDR_LEN = 40;
constexpr size_t IP6_MIN_LEN = ETH_HDR_LEN + IP6_HDR_LEN;

constexpr size_t PROTO_ICMP6 = 58;

constexpr size_t NDP_LEN = 24;
constexpr size_t NDP_MIN_LEN = IP6_MIN_LEN + NDP_LEN;
constexpr size_t MAX_TTL = 255;

enum class AddressType {
	UNKNOWN,
	GLOBAL_UNICAST,
	UNIQUE_LOCAL_UNICAST,
	LINK_SCOPED_UNICAST,
	MULTICAST,
};

} // namespace ip6_dad_restrict

#endif
