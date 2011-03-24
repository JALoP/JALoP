#
# Dumping grounds for functions to add to the 'Configure' context.
# The CheckPKG* style functions were borrowed from 
# www.scons.org/wiki/UsingPkgConfig

def CheckPKGConfig(context, version):
	context.Message('Checking for pkg-config... ' )
	ret = context.TryAction('pkg-config --atleast-pkgconfig-version=%s' % version)[0]
	context.Result( ret )
	return ret

def CheckPKG(context, name):
	context.Message('Checking for %s...' % name )
	ret = context.TryAction('pkg-config --exists \'%s\'' % name)[0]
	context.Result( ret )
	return ret

def CheckPKGAtLeastVersion(context, name, version):
	context.Message('Checking for %s >= %s...' % (name, version) )
	ret = context.TryAction('pkg-config --atleast-version="%s" \'%s\'' % (version, name))[0]
	context.Result( ret )
	return ret

def CheckPKGExactVersion(context, name, version):
	context.Message('Checking for %s == %s...' % (name, version) )
	ret = context.TryAction('pkg-config --exact-version="%s" \'%s\'' % (version, name))[0]
	context.Result( ret )
	return ret

def CheckPKGAtMostVersion(context, name, version):
	context.Message('Checking for %s... <= %s...' % (name, version) )
	ret = context.TryAction('pkg-config --max-version="%s" \'%s\'' % (version, name))[0]
	context.Result( ret )
	return ret

