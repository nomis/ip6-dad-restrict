project('ip6-dad-restrict',
	['c', 'cpp'],
	default_options: [
		'c_std=c11',
		'cpp_std=c++14',
		'warning_level=3',
		'werror=true',
	],
	version: '0.0.1',
	license: 'GPL3+',
	meson_version: '>=0.53',
)

source_files = [
	'src/application.cc',
	'src/capture.cc',
	'src/command_line.cc',
	'src/main.cc',
	'src/print_error.cc',
	'src/to_string.cc',
	vcs_tag(input: 'src/version.h.in', output: 'version.h'),
]

c = meson.get_compiler('c')
cpp = meson.get_compiler('cpp')

c_args = ['-D_POSIX_C_SOURCE=200809L']

executable('ip6-dad-restrict',
	source_files,
	cpp_args: c_args,
	dependencies: [
		dependency('boost', modules: [
			'program_options',
			'system',
		]),
		dependency('pcap')
	],
	install: true)

run_target('cppcheck',
	command: [
		'cppcheck',
		'--project=' + join_paths(meson.current_build_dir(), 'compile_commands.json'),
		'--enable=all',
		'--inline-suppr',
	] + source_files)
