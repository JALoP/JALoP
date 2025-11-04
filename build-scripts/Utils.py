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
	variant = env['variant']
	env.MergeFlags("-L%s/%s/src/%s/src/ -l%s" % (env['SOURCE_ROOT'], variant, libdir, libname))

def install_for_build(env, dest, target):
	variant = env['variant']
	env.Default(env.Install("%s/%s/%s" % (env['SOURCE_ROOT'], variant, dest), target))

def rhel_version():
    with open('/etc/os-release', 'r') as f:
        kv = {}
        for line in f:
            line = line.strip()
            if not line or '=' not in line:
                continue
            k, v = line.split('=', 1)
            kv[k] = v.strip().strip('"')
    if kv.get('ID') == 'rhel' or kv.get('ID') == 'centos':
        return int(kv.get('VERSION_ID', '').split('.')[0])
    else:
        raise ValueError(f"invalid os: {kv.get('ID')}")
