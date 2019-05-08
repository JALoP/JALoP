import sys
import os
import platform
import SCons.Util
sys.path.append(os.getcwd() + '/3rd-party/build')
sys.path.append(os.getcwd() + '/build-scripts')

import ConfigDotH
import ConfigHelpers
import PackageCheckHelpers
from Utils import recursive_glob

from InstallOptions import add_install_options
from InstallOptions import update_env_with_install_paths
add_install_options()
AddOption('--no-selinux', dest='DISABLE_SELINUX',
		action='store_true', default=False,
		help='Disable support for SE Linux.')
AddOption('--no-release', dest='DISABLE_RELEASE',
		action='store_true', default=False,
		help='Disable optimized release builds.')
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
	'openssl'  	: ['openssl', '0.9.8'],
	'libconfig'	: ['libconfig', '1.3.2'],
	'vortex'   	: ['vortex-1.1', '1.1.9'],
	'vortex_tls'	: ['vortex-tls-1.1', '1.1.9'],
	'libxml2'	: ['libxml-2.0', '2.6.26'],
	'xmlsec1'	: ['xmlsec1', '1.2.9'],
	'xmlsec1_openssl'	: ['xmlsec1-openssl', '1.2.9'],
	'libcurl'	: ['libcurl', '4.1.1'],
	'apr_util'	: ['apr-util-1', '0.3.9'],
	}

# flags are shared by both debug and release builds
default_ccflags = ' -Wall -W -Wundef -Wshadow -Wmissing-noreturn -Wformat=2 -Wmissing-format-attribute '
default_ccflags += ' -Wextra -Wno-unreachable-code -fexceptions'
default_ccflags += ' -DSHARED -D__EXTENSIONS__ -D_GNU_SOURCE -DHAVE_VA_COPY '
default_cflags = ' -std=gnu99 '


# The debug and release flags are applied to the appropriate environments.
# This script will build both debug and release version at the same time,
# common flags should get added to the 'flags' variable. Flags sepcific to a
# particular build configuration should get added to the appropriate spot.
extra_debug_ccflags = '-DDEBUG -g'.split()

profiling_ccflags = '-fprofile-arcs -ftest-coverage'.split()
profiling_ldflags = profiling_ccflags

stack_protector_ccflags = '-fstack-protector --param=ssp-buffer-size=4'.split()

extra_release_ccflags = '-DNDEBUG -D_FORTIFY_SOURCE=2 -g -O3'.split()
debug_env = Environment(ENV=os.environ, tools=['default','doxygen', 'test_dept', 'gcc', 'g++'],
		parse_flags= default_ccflags,
		toolpath=['./3rd-party/site_scons/site_tools/', './build-scripts/site_tools/'])
debug_env['JALOP_VERSION_STR'] = '1.0'
update_env_with_install_paths(debug_env)
# There is a quirk in scons where it likes to try and normalize the path. Basically, if you use
# PrependENVPath, it will scan for duplicate path entries, and keep the the first entry, however
# if you use AppendENVPath, it will scan for duplicate path entries, and keep the last.  Since
# we're trying to adopt the user's environment here. Scons won't do this until you either append
# or prepend a path element, so we need to do a prepend (to keep the user's path in the correct
# order first. Since the build-scripts is all custom code, there should be no harm in prepending
# it to the PATH.
debug_env.PrependENVPath('PATH', os.path.join(os.getcwd(), 'build-scripts'))

debug_env.Append(CFLAGS=default_cflags)

if os.environ.has_key('LD'):
	debug_env['LINK'] = os.environ['LD']
for t in ['CC', 'CXX', 'CPP' ]:
	if os.environ.has_key(t):
		debug_env[t] = os.environ[t]

debug_env['SOURCE_ROOT'] = str(os.getcwd())
debug_env['HAVE_SELINUX'] = False;
debug_env.MergeFlags(' -D_POSIX_C_SOURCE=200112L ')

if platform.system() == 'SunOS':
	debug_env.Replace(RPATHPREFIX = '-Wl,-R')
	debug_env.PrependENVPath('PKG_CONFIG_PATH',
			'/usr/local/ssl/lib/pkgconfig:/usr/local/lib/pkgconfig')
	debug_env.MergeFlags({'LINKFLAGS':'-L/usr/local/lib -Wl,-R,/usr/local/lib -Wl,-R,/usr/local/ssl/lib'.split()})
	debug_env.PrependENVPath('PATH', '/usr/sfw/bin')
	debug_env.MergeFlags('-lsocket')
	debug_env["bdb_cflags"] = "-I/usr/local/BerkeleyDB.4.7/include".split()
	debug_env["bdb_ldflags"] = "-L/usr/local/BerkeleyDB.4.7/lib \
					-Wl,-R,/usr/local/BerkeleyDB.4.7/lib \
					-ldb".split()
else:
	debug_env["bdb_ldflags"] = "-ldb"
	debug_env["bdb_cflags"] = ""

def merge_with_os_env(env):
	if os.environ.has_key('LIBPATH'):
		env.MergeFlags({'LIBPATH':os.environ['LIBPATH'].split(':')})
	if os.environ.has_key('INCLUDE'):
		env.MergeFlags({'CPPPATH':os.environ['INCLUDE'].split(':')})
	if os.environ.has_key('LDFLAGS'):
		env.MergeFlags(env.ParseFlags(os.environ['LDFLAGS']))
	if os.environ.has_key('CCFLAGS'):
		env.MergeFlags(env.ParseFlags(os.environ['CCFLAGS']))
	if os.environ.has_key('CFLAGS'):
		# ParseFlags treats things that are not defines, include
		# paths, linker flags, etc as things that should be dropped
		# into CCFLAGS, which is used for both C and C++ compiles.
		d = env.ParseFlags(os.environ['CFLAGS'])
		d['CFLAGS'] = d['CFLAGS'] + d['CCFLAGS']
		d['CCFLAGS'] = []
		env.MergeFlags(d)
	if os.environ.has_key('CXXFLAGS'):
		d = env.ParseFlags(os.environ['CXXFLAGS'])
		if 'CXXFLAGS' not in d.keys():
			d['CXXFLAGS'] = d['CFLAGS'] + d['CCFLAGS']
		else:
			d['CXXFLAGS'] = d['CXXFLAGS'] + d['CCFLAGS'] + d['CCFLAGS']
		d['CCFLAGS'] = []
		d['CFLAGS'] = []
		env.MergeFlags(d)
merge_with_os_env(debug_env)


if not (GetOption("clean") or GetOption("help")):
	conf = Configure(debug_env, custom_tests = { 'CheckPKGConfig': ConfigHelpers.CheckPKGConfig,
						     'CheckPKG': ConfigHelpers.CheckPKG,
						     'CheckPKGAtLeastVersion': ConfigHelpers.CheckPKGAtLeastVersion,
						     'CheckPKGAtMostVersion': ConfigHelpers.CheckPKGAtMostVersion,
						     'CheckPKGExactVersion': ConfigHelpers.CheckPKGExactVersion,
						     'CheckLibUUID': PackageCheckHelpers.CheckLibUUID,
						     'CheckSeLinux': PackageCheckHelpers.CheckSeLinux,
						     'CheckProducerLibConfigDotH': ConfigDotH.CheckProducerLibConfigDotH,
						     'CheckByteswap': PackageCheckHelpers.CheckByteswap,
						   })

	if not conf.CheckCC():
		Exit(-1)

	if not conf.CheckCXX():
		Exit(-1)

	if not conf.CheckHeader("test-dept.h"):
		Exit(-1)

	if not conf.CheckPKGConfig(pkg_config_version):
		Exit(-1)

	if conf.CheckByteswap():
		debug_env.MergeFlags('-DHAVE_BYTESWAP_H')

	if not conf.CheckLibUUID():
		Exit(-1)

	if platform.system() == 'Linux':
		if GetOption('DISABLE_SELINUX'):
			print 'Disabling SELinux support';
		elif not conf.CheckSeLinux():
			print 'Failed to find SELinux headers on Linux. If you are sure \
this is want you want, this is OK, re-run scons with the \
--no-selinux options'
		else:
			debug_env['HAVE_SELINUX'] = True
			debug_env['selinux_ldflags'] = '-lselinux'

	if not conf.CheckProducerLibConfigDotH():
		Exit(-1)

	for (pkg, version) in packages_at_least.values():
		if not conf.CheckPKGAtLeastVersion(pkg, version):
			Exit(-1)


	conf.Finish()

	checkEnv = debug_env.Clone()
	checkEnv.MergeFlags(checkEnv['bdb_cflags'])
	checkEnv.MergeFlags(checkEnv['bdb_ldflags'])
	bdbconf = Configure(checkEnv, custom_tests = {
						'CheckBDB': PackageCheckHelpers.CheckBDB
						 })
	if not bdbconf.CheckBDB():
		Exit(-1)
	bdbconf.Finish()

	for key, (pkg, version) in packages_at_least.items():
		def addCFLAGS(debug_env, cmd, unique=1):
			debug_env[key + "_cflags"] = cmd.split()
		def addLDFLAGS(debug_env, cmd, unique=1):
			debug_env[key + "_ldflags"] = cmd.split()

		debug_env.ParseConfig('pkg-config --cflags %s' % pkg, function=addCFLAGS)
		debug_env.ParseConfig('pkg-config --libs %s' % pkg, function=addLDFLAGS)
else:
	for key, _ in packages_at_least.items():
		debug_env[key + "_cflags"] = ""
		debug_env[key + "_ldflags"] = ""

def add_lfs_cflags(debug_env, cmd, unique=1):
	debug_env["lfs_cflags"] = cmd.split()

debug_env.ParseConfig('getconf LFS_CFLAGS', function=add_lfs_cflags)

# linker flags for libuuid
debug_env["libuuid_ldflags"] = "-luuid"


all_tests = debug_env.Alias('tests')

# Clone the debug environment after it's been configured, no need to re-run all the conf checks

release_env = debug_env.Clone()

# add appropriate flags for debug/release
release_env.Prepend(CCFLAGS=extra_release_ccflags)
debug_env.Prepend(CCFLAGS=extra_debug_ccflags)

if debug_env['CC'] == 'gcc':
	debug_env.Prepend(CCFLAGS=profiling_ccflags, LINKFLAGS=profiling_ldflags)
	# Stack protector wasn't added to GCC until 4.x, disable it for earlier versions (i.e. 3.x compilers on solaris).
	(major, _, _) = debug_env['CCVERSION'].split('.')
	if int(major) >= 4:
		debug_env.Prepend(CCFLAGS=stack_protector_ccflags)

# coverage target
lcov_output_dir = "cov"
lcov_output_file = "app.info"
lcov_output_path = os.path.join(lcov_output_dir, lcov_output_file)

coverage = debug_env.Alias(target=lcov_output_dir, source=None,
		action=["mkdir -p ${TARGET}",
			"lcov -q --directory ${TARGET}/.. -b ${TARGET}/.. --capture --output-file %s" % lcov_output_path,
			"lcov -q --remove %s /usr/\* --output-file %s" % (lcov_output_path, lcov_output_path),
			"lcov -q --remove %s 3rd-party/\* --output-file %s" % (lcov_output_path, lcov_output_path),
			"lcov -q --remove %s src/\*/test/\* --output-file %s" % (lcov_output_path, lcov_output_path),
			"lcov -q --remove %s src/test_utils/\* --output-file %s" % (lcov_output_path, lcov_output_path),
			"cd ${TARGET} && genhtml --show-details -k %s" % (lcov_output_file),
			])
debug_env.AlwaysBuild(coverage)

debug_env.Clean(coverage, ['#cov'])
debug_env.Clean('profiling-files', recursive_glob('.', '*.gcno'))
debug_env.Clean(coverage, recursive_glob('.', '*.gcda'))
if GetOption("clean"):
	debug_env.Default(coverage)
	debug_env.Default('profiling-files')
else:
	debug_env.Depends(target=coverage, dependency=all_tests)


# build release and debug versions in seperate directories
debug_env['variant'] = 'debug';
release_env['variant'] = 'release';
SConscript('SConscript', variant_dir='debug', duplicate=0, exports={'env':debug_env, 'all_tests':all_tests})
if not GetOption("DISABLE_RELEASE"):
	SConscript('SConscript', variant_dir='release', duplicate=0, exports={'env':release_env, 'all_tests':all_tests})

if GetOption("clean"):
	debug_env.Clean('debug_dir', 'debug')
	debug_env.Clean('release_dir', 'release')
	debug_env.Default('debug_dir')
	debug_env.Default('release_dir')

# docs only need to get built once, and it shouldn't matter if the debug or
# release flags are used.

SConscript('doc/SConscript', duplicate=0, exports={'env':debug_env})

