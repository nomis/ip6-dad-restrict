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
#include "command_line.h"

#include <libgen.h>
#include <stdlib.h>
#include <sysexits.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <typeinfo>
#include <vector>

#include <boost/format.hpp>
#include <boost/program_options.hpp>

#include "print_error.h"
#include "version.h"

using ::boost::format;
using ::std::cerr;
using ::std::cout;
using ::std::endl;
using ::std::flush;
using ::std::string;
using ::std::vector;

namespace po = boost::program_options;

namespace ip6_dad_restrict {

const string CommandLine::DEFAULT_PROGRAM_NAME{"ip6-dad-restrict"};
string CommandLine::internal_name_{CommandLine::DEFAULT_PROGRAM_NAME};
string CommandLine::display_name_{CommandLine::DEFAULT_PROGRAM_NAME};

void CommandLine::update_name(const string &program_name) {
	display_name_ = program_name;
}

void CommandLine::parse(int argc, const char* const argv[]) {
	if (argc > 0) {
		update_name(argv[0]);
	}

	po::options_description all_opts;

	// LCOV_EXCL_BR_START
	po::options_description main_opts{"Options"};
	main_opts.add_options()
		("interface,i",
				po::value<string>()->value_name("INTERFACE"),
				"listen and transmit on INTERFACE")
		("mac,m",
				po::value<vector<string>>()->value_name("MAC"),
				"apply restrictions to MAC address prefix")
		;

	po::options_description misc_opts{"Miscellaneous"};
	misc_opts.add_options()
		("help,h", po::bool_switch(), "display this help and exit")
		("version,V", po::bool_switch(), "output version information and exit")
		;

	all_opts.add(main_opts);
	all_opts.add(misc_opts);
	// LCOV_EXCL_BR_STOP

	try {
		po::store(po::command_line_parser(argc, argv)
			.style(po::command_line_style::unix_style & ~po::command_line_style::allow_guessing)
			.options(all_opts)
			.run(), variables_);

		if (variables_["help"].as<bool>()) {
			display_usage(all_opts);
			exit(EXIT_SUCCESS);
		}

		po::notify(variables_);

		if (variables_["version"].as<bool>()) {
			display_version();
			exit(EXIT_SUCCESS);
		}
	} catch (std::exception &e) {
		print_error(format("%1%"), e);
		cerr << format("Try '%1% %2%' for more information.") % display_name_ % "-h" << endl;
		exit(EX_USAGE);
	}
}

void CommandLine::display_usage(const po::options_description &options) const {
	cout << format("Usage: %1% [OPTION]...") % display_name_ << "\n\n";
	cout << "Run COMMAND with standard output and standard error copied to each FILE\n"
			"while maintaining the original standard output and standard error as normal.\n";
	cout << "\n" << options << endl;
}

void CommandLine::display_version() const {
	cout << DEFAULT_PROGRAM_NAME << " " << VERSION << "\n";
	cout << "Copyright 2020  Simon Arlott\n";
	cout << format(
		"Licence GPLv3+: GNU GPL version 3 or later <%1%>.\n"
		"This program comes with ABSOLUTELY NO WARRANTY, to the extent permitted by law.\n"
		"This is free software: you are free to change and redistribute it.\n")
		% "https://gnu.org/licenses/gpl.html";
	cout << flush;
}

bool CommandLine::flag(const string &name) const {
	return variables_[name].as<bool>();
}

string CommandLine::text(const string &name) const {
	return variables_[name].as<string>();
}

const vector<string>& CommandLine::list(const string &name) const {
	const auto& value = variables_[name];

	if (!value.empty()) {
		return value.as<vector<string>>();
	} else {
		return empty_list_;
	}
}

} // namespace ip6_dad_restrict
