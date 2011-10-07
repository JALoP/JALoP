"""
These are helper functions needed by multiple SConscript and SConstruct files.
"""
import fnmatch
import os

def recursive_glob(source_dir, pattern):
	"Recursively Find all files in source_dir that match pattern."
	matches = []
	for root, dirnames, filenames in os.walk(source_dir):
		for filename in fnmatch.filter(filenames, pattern):
			matches.append(os.path.join(root, filename))
	return matches

def add_project_lib(env, libdir, libname):
	variant = 'debug'
	if (env['release']):
		variant = 'release'
	env.MergeFlags("-L%s/%s/src/%s/src/ -l%s" % (env['SOURCE_ROOT'], variant, libdir, libname))

def install_for_build(env, dest, target):
	variant = 'debug'
	if (env['release']):
		variant = 'release'
	env.Default(env.Install("%s/%s/%s" % (env['SOURCE_ROOT'], variant, dest), target))
