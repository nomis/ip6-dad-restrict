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
#ifndef IP6_DAD_RESTRICT_APPLICATION_H_
#define IP6_DAD_RESTRICT_APPLICATION_H_

#include "command_line.h"

namespace ip6_dad_restrict {

class Application {
public:
	Application() = default;
	~Application() = default;

	int run(int argc, const char* const argv[]);

	Application(const Application&) = delete;
	Application& operator=(const Application&) = delete;

private:
	CommandLine command_line_;
};

} // namespace ip6_dad_restrict

#endif
