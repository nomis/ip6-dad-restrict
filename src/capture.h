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
#ifndef IP6_DAD_RESTRICT_CAPTURE_H_
#define IP6_DAD_RESTRICT_CAPTURE_H_

#include <pcap/pcap.h>

#include <array>
#include <memory>
#include <string>

namespace ip6_dad_restrict {

enum class AddressType {
	UNKNOWN,
	GLOBAL_UNICAST,
	UNIQUE_LOCAL_UNICAST,
	LINK_SCOPED_UNICAST,
	MULTICAST,
};

struct DADPacket {
	DADPacket(const std::array<unsigned char,6> source_mac, const std::array<unsigned char,16> target_ip) : source_mac(source_mac), target_ip(target_ip) {};
	~DADPacket() = default;

	bool eui64() const;
	AddressType type() const;
	bool bad() const;

	const std::array<unsigned char,6> source_mac;
	const std::array<unsigned char,16> target_ip;
};

class Capture {
public:
	Capture(const std::string &interface);
	~Capture() = default;

	Capture(const Capture&) = delete;
	Capture& operator=(const Capture&) = delete;

	explicit operator bool() const { return handle_.get(); }

	std::unique_ptr<DADPacket> next();

private:
	std::shared_ptr<pcap_t> handle_;
};

} // namespace ip6_dad_restrict

#endif
