"""
These are functions to create the config.h file.
"""
import os

def CheckProducerLibConfigDotH(context):
	context.Message("Checking how to get process name from /proc for producer library...")
	defines = __proc_name_from_proc()
	for key, val in defines.items():
		context.env[key] = val
	context.Result(1)
	return 1

def __proc_name_from_proc():
	"""
	Check if we can get the current process name from somewhere
	in /proc.  On linux, we can usually get the process name
	from /proc/$$/exe, and on Solaris we can usually get the
	current process name from /proc/$$/path/a.out.
	"""
	defines = {"jalp_have_procfs":0, "jalp_process_name_path":""}
	pid = os.getpid()

	if os.path.islink("/proc/%d/exe" % pid):
		defines["jalp_have_procfs"] = 1
		defines["jalp_process_name_path"] = "/proc/%\" PRIdMAX \"/exe"
	elif os.path.islink("/proc/%d/path/a.out" % pid):
		defines["jalp_have_procfs"] = 1
		defines["jalp_process_name_path"] = "/proc/%\" PRIdMAX \"/path/a.out"

	return defines

def print_config(msg, two_dee_iterable):
	"Print out a dictionary."
	print
	print msg
	print
	for key, val in two_dee_iterable:
		print "    %-20s %s" % (key, val)
	print

def config_h_build(target, source, env):
	"""
	Build config.h file.  Uses values defined in config_h_defines to
	replace values in the config.h.in file. config_h_defines is just
	taken from all the values in the environment.
	"""

	# this is where you put all of your custom configuration values
	config_h_defines = env.Dictionary()

	#print_config("Generating config.h with the following settings:",
	#		config_h_defines.items())

	for a_target, a_source in zip(target, source):
		config_h = file(str(a_target), "w")
		config_h_in = file(str(a_source), "r")
		config_h.write(config_h_in.read() % config_h_defines)
		config_h_in.close()
		config_h.close()
