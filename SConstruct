import sys
import os
import platform
sys.path.append(os.getcwd() + '/3rd-party/build')
sys.path.append(os.getcwd() + '/build-scripts')

import ConfigHelpers
import PackageCheckHelpers
from Utils import recursive_glob

# Update package version here, add actual checks below
pkg_config_version = '0.21'

# Only add packages to this list that install package config files.
# For each package in this map, make sure the installed version is at least
# the version specified.
#
# NOTE: Adding the package here only checks for the existence of package, and
# does not add the required cflags/libs to environment. This is intentional.
# Add the cflags/library flags only where they are needed. This can be done
# using the 'ParseConfig' method of the Environment object:
#      env.ParseConfig("pkg-config libconfig --cflags --libs")
#
# Packages are not added here since doing so would result in everything
# depending every library.
#
# The 'key' must contain only a-z, A-Z, and '_' characters.
# The array must be the name of the package (according to pkg-config) and the
# minimum version to use.
#
# When the package is found, this script will add a key_cflags and key_ldflags
# to the Enviroment. These may be used when building various targets to ensure
# the proper flags are added. For example, if the 'foo' program needs openssl,
# something like the following should be added to the SConscript for 'foo'
#
# cflags = env['openssl_cflags']
# ldflags = env['openssl_ldflags']
# env.Program('foo', 'foo.c', parse_flags=(cflags + " " + ldflags))
#

packages_at_least = {
	'openssl'  : ['openssl', '0.9.7'],
	'libconfig': ['libconfig', '1.3.2'],
	'vortex'   : ['vortex-1.1', '1.1.7'],
	'xerces'   : ['xerces-c', '3.1.1'],
	}

# flags are shared by both debug and release builds
warningFlags = ' -Wall -W -Wundef -Wshadow -Wmissing-noreturn -Wformat=2 -Wmissing-format-attribute -Wextra -Werror -D_FORTIFY_SOURCE=2 -fexceptions   '
flags = warningFlags + ' -DSHARED -D__EXTENSIONS__ -D_GNU_SOURCE_ -g -DHAVE_VA_COPY '

# The debug and release flags are applied to the appropriate environments.
# This script will build both debug and release version at the same time,
# common flags should get added to the 'flags' variable. Flags sepcific to a
# particular build configuration should get added to the appropriate spot.
debug_flags = ' -Wunreachable-code -DDEBUG -fprofile-arcs -ftest-coverage '
debug_ldflags = ' -fprofile-arcs -ftest-coverage '
release_flags = ' -O3 -DNDEBUG -Wno-unreachable-code'
debug_env = Environment(tools=['default','doxygen', 'test_dept', 'gcc', 'g++'],
		toolpath=['./3rd-party/site_scons/site_tools/', './build-scripts/site_tools/'])
debug_env.Append(CCFLAGS=flags, CFLAGS='-std=gnu99')
if platform.system() == 'SunOS':
	debug_env.Append(CCFLAGS=' -D_POSIX_C_SOURCE=200112L ')

# Stack protector wasn't added to GCC until 4.x, disable it for earlier versions (i.e. 3.x compilers on solaris).
(major, _, _) = debug_env['CCVERSION'].split('.')
if int(major) >= 4:
	debug_env.Append(CCFLAGS=' -fstack-protector --param=ssp-buffer-size=4')

conf = Configure(debug_env, custom_tests = { 'CheckPKGConfig': ConfigHelpers.CheckPKGConfig,
				       'CheckPKG': ConfigHelpers.CheckPKG,
				       'CheckPKGAtLeastVersion': ConfigHelpers.CheckPKGAtLeastVersion,
				       'CheckPKGAtMostVersion': ConfigHelpers.CheckPKGAtMostVersion,
				       'CheckPKGExactVersion': ConfigHelpers.CheckPKGExactVersion,
				       'CheckSantuario': PackageCheckHelpers.CheckSantuario,
					   })

if not conf.CheckCC():
	Exit(-1)

if not conf.CheckCXX():
	Exit(-1)

if not conf.CheckHeader("test-dept.h"):
	Exit(-1)

if not conf.CheckPKGConfig(pkg_config_version):
	Exit(-1)

if not conf.CheckSantuario():
	Exit(-1)

for (pkg, version) in packages_at_least.values():
	if not conf.CheckPKGAtLeastVersion(pkg, version):
		Exit(-1)

conf.Finish()

for key, (pkg, version) in packages_at_least.items():
	def addCFLAGS(debug_env, cmd, unique=1):
		debug_env[key + "_cflags"] = cmd
	def addLDFLAGS(debug_env, cmd, unique=1):
		debug_env[key + "_ldflags"] = cmd

	debug_env.ParseConfig('pkg-config --cflags %s' % pkg, function=addCFLAGS)
	debug_env.ParseConfig('pkg-config --libs %s' % pkg, function=addLDFLAGS)

# add linker flags for santuario
debug_env["santuario_ldflags"] = "-lxml-security-c"

debug_env.AppendENVPath('PATH', os.path.join(os.getcwd(), 'build-scripts'))

all_tests = debug_env.Alias('tests')

# Clone the debug environment after it's been configured, no need to re-run all the conf checks
release_env = debug_env.Clone()

# add appropriate flags for debug/release
release_env.Append(CCFLAGS=release_flags)
debug_env.Append(CCFLAGS=debug_flags, LINKFLAGS=debug_ldflags)


# coverage target
lcov_output_dir = "cov"
lcov_output_file = "app.info"
lcov_output_path = os.path.join(lcov_output_dir, lcov_output_file)

coverage = debug_env.Alias(target=lcov_output_dir, source=None, 
		action=["mkdir -p ${TARGET}",
			"lcov -q --directory ${TARGET}/.. -b ${TARGET}/.. --capture --output-file %s" % lcov_output_path,
			"lcov -q --remove %s /usr/\* --output-file %s" % (lcov_output_path, lcov_output_path),
			"lcov -q --remove %s 3rd-party/\* --output-file %s" % (lcov_output_path, lcov_output_path),
			"cd ${TARGET} && genhtml --show-details -k %s" % (lcov_output_file),
			])
debug_env.AlwaysBuild(coverage)

debug_env.Clean(coverage, ['#cov'])
debug_env.Clean(coverage, recursive_glob('.', '*.gcda'))
if GetOption("clean"):
	debug_env.Default(coverage)
else:
	debug_env.Depends(target=coverage, dependency=all_tests)


# build release and debug versions in seperate directories
SConscript('SConscript', variant_dir='debug', duplicate=0, exports={'env':debug_env, 'all_tests':all_tests})
SConscript('SConscript', variant_dir='release', duplicate=0, exports={'env':release_env, 'all_tests':all_tests})

# docs only need to get built once, and it shouldn't matter if the debug or
# relase flags are used.

SConscript('doc/SConscript', duplicate=0, exports={'env':debug_env})
