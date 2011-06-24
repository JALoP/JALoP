"""
These are functions to add to the configure context.
"""

def __checkCanLink(context, source, source_type, message_libname, real_libs=[]):
	"""
	Check that source can be successfully compiled and linked against real_libs.

	Keyword arguments:
	source -- source to try to compile
	source_type -- type of source file, (probably should be ".c")
	message_libname -- library name to show in the message output from scons
	real_libs -- list of actual libraries to link against (defaults to a list
				 with one element, the value of messager_libname)
	"""
	if not real_libs:
		real_libs = [message_libname]

	context.Message("Checking for %s..." % message_libname)
	libsave = context.env.get('LIBS')
	context.env.AppendUnique(LIBS=real_libs)
	ret = context.TryLink(source, source_type)
	context.Result( ret )
	if libsave is None:
		del(context.env['LIBS'])
	else:
		context.env['LIBS'] = libsave
	return ret


santuario_source = '''
#include <xsec/framework/XSECProvider.hpp>
int main () {
	XSECPlatformUtils::Initialise();
	return 0;
}
'''
def CheckSantuario(context):
	return __checkCanLink(context, santuario_source, ".cpp", "santuario", ["xml-security-c", "xerces-c"])



libuuid_source = '''
#include <uuid/uuid.h>
int main() {
	uuid_t uu;
	char uuid_str[37];
	uuid_generate(uu);
	uuid_unparse(uu, uuid_str);
	return 0;
}
'''
def CheckLibUUID(context):
	return __checkCanLink(context, libuuid_source, ".c", "libuuid", ["uuid"])
