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
#ifndef IP6_DAD_RESTRICT_COMMAND_LINE_H_
#define IP6_DAD_RESTRICT_COMMAND_LINE_H_

#include <string>
#include <vector>

#include <boost/program_options.hpp>

namespace ip6_dad_restrict {

class CommandLine {
public:
	CommandLine() = default;
	~CommandLine() = default;

	static std::string internal_name() { return internal_name_; }
	static std::string display_name() { return display_name_; }

	void parse(int argc, const char* const argv[]);

	bool flag(const std::string &name) const;
	std::string text(const std::string &name) const;
	const std::vector<std::string>& list(const std::string &name) const;

	std::string interface() const { return text("interface"); }

	CommandLine(const CommandLine&) = delete;
	CommandLine& operator=(const CommandLine&) = delete;

private:
	void update_name(const std::string &program_name);
	void display_usage(const boost::program_options::options_description &options) const;
	void display_version() const;

	static const std::string DEFAULT_PROGRAM_NAME;
	static const std::string CRON_MODE_NAME;
	static std::string internal_name_;
	static std::string display_name_;

	boost::program_options::variables_map variables_;
	const std::vector<std::string> empty_list_{};
};

} // namespace ip6_dad_restrict

#endif
