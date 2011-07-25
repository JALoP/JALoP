from SCons.Script.Main import AddOption
import os
def add_install_options():
	AddOption('--prefix', dest='PREFIX',
		nargs=1, type='string',
		action='store',
		metavar='DIR',
		default='/',
		help='install architecture-independent files in PREFIX')

	AddOption('--exec-prefix', dest='EPREFIX',
		nargs=1, type='string',
		action='store',
		metavar='DIR',
		default='$PREFIX',
		help='install architecture-dependent files in EPREFIX')

	AddOption('--bindir', dest='BINDIR',
		nargs=1, type='string',
		action='store',
		metavar='DIR',
		default='$EPREFIX/bin',
		help='user executables [EPREFIX/bin]')

	AddOption('--sbindir', dest='SBINDIR',
		nargs=1, type='string',
		action='store',
		metavar='DIR',
		default='$EPREFIX/sbin',
		help='system admin executables [EPREFIX/sbin]')

	AddOption('--sysconfdir', dest='SYSCONFDIR',
		nargs=1, type='string',
		action='store',
		metavar='DIR',
		default='$PREFIX/etc',
		help='read-only single-machine data [PREFIX/etc]')

	AddOption('--localstatedir', dest='LOCALSTATEDIR',
		nargs=1, type='string',
		action='store',
		metavar='DIR',
		default='$PREFIX/var',
		help='user executables [PREFIX/var]')

	AddOption('--libdir', dest='LIBDIR',
		nargs=1, type='string',
		action='store',
		metavar='DIR',
		default='$EPREFIX/lib',
		help='user executables [EPREFIX/lib]')

	AddOption('--includedir', dest='INCLUDEDIR',
		nargs=1, type='string',
		action='store',
		metavar='DIR',
		default='/usr/include',
		help='user executables [usr/include]')

	AddOption('--datarootdir', dest='DATAROOTDIR',
		nargs=1, type='string',
		action='store',
		metavar='DIR',
		default='$PREFIX/share',
		help='user executables [PREFIX/share]')

	AddOption('--mandir', dest='MANDIR',
		nargs=1, type='string',
		action='store',
		metavar='DIR',
		default="$DATAROOTDIR",
		help='man documentation [DATAROOTDIR]. The man pages will be'
			'installed to a subdir (named man) of the given directory')

	AddOption('--docdir', dest='DOCDIR',
		nargs=1, type='string',
		action='store',
		metavar='DIR',
		default="$DATAROOTDIR/doc/jalop",
		help='documentation root [DATAROOTDIR/doc/jalop]')

	AddOption('--htmldir', dest='HTMLDIR',
		nargs=1, type='string',
		action='store',
		metavar='DIR',
		default="$DOCDIR",
		help='html documentation [DOCDIR]')
env_names = """PREFIX EPREFIX BINDIR SBINDIR
			SYSCONFDIR LOCALSTATEDIR LIBDIR
			INCLUDEDIR DATAROOTDIR MANDIR
			DOCDIR HTMLDIR""".split()
def update_env_with_install_paths(env):
	if not env.has_key('DESTDIR'):
		env['DESTDIR'] = '/'
	for path in env_names:
		env[path] = env.GetOption(path)
	# add some usefull exports...
	env['JALOP_SCHEMAS_ROOT'] = (env.subst(env['DATAROOTDIR']) +
			'/jalop-v' + env['JALOP_VERSION_STR'] + '/schemas')
