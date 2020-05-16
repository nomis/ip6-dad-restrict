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
#include "application.h"

#include <sysexits.h>
#include <array>
#include <iostream>
#include <memory>

#include <boost/asio.hpp>
#include <boost/format.hpp>
#include <boost/system/error_code.hpp>

#include "capture.h"
#include "command_line.h"
#include "print_error.h"
#include "transmit.h"

using ::std::array;
using ::std::cout;
using ::std::endl;
using ::std::unique_ptr;

namespace ip6_dad_restrict {

int Application::run(int argc, const char* const argv[]) {
	command_line_.parse(argc, argv);

	Capture capture{command_line_.interface()};
	Transmit transmit{command_line_.interface()};

	while (capture && transmit) {
		unique_ptr<DADPacket> packet = capture.next();
		if (packet && packet->bad()) {
			transmit.transmit_ndp_na_block_dad(*packet);
		}
	}

	return EXIT_SUCCESS;
}

} // namespace ip6_dad_restrict
