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
#ifndef IP6_DAD_RESTRICT_PRINT_ERROR_H_
#define IP6_DAD_RESTRICT_PRINT_ERROR_H_

#include <exception>
#include <string>

#include <boost/format.hpp>
#include <boost/system/error_code.hpp>

#include "to_string.h"

namespace ip6_dad_restrict {

void print_error(const boost::format &message);
void print_error(boost::format message, const boost::system::error_code &ec);
void print_error(boost::format message, const std::exception &e);
void print_system_error(boost::format message, std::string cause = errno_to_string());

} // namespace ip6_dad_restrict

#endif
