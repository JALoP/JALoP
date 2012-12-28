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

selinux_source = '''
#include <selinux/selinux.h>
int main() {
	security_context_t ctx;
	getpeercon(0, &ctx);
	return 0;
}
'''
def CheckSeLinux(context):
	return __checkCanLink(context, selinux_source, '.cpp', 'selinux', ['selinux'])

byteswap_source = '''
#include <byteswap.h>
#include <stdint.h>
int main() {
	uint16_t b16 = 0x00FF;
	uint32_t b32 = 0x0011EEFF;
	uint64_t b64 = 0x00112233CCDDEEFF;

	bswap_16(b16);
	bswap_32(b32);
	bswap_64(b64);
	return 0;
}
'''
def CheckByteswap(context):
	context.Message("Checking for byteswap.h...")
	ret = context.TryCompile(byteswap_source, '.c')
	context.Result( ret )
	return ret


bdb_source = '''
#include <db.h>

#if defined(DB_VERSION_MAJOR) && DB_VERSION_MAJOR >= 4
	#if DB_VERSION_MAJOR == 4
		#if defined(DB_VERSION_MINOR) && DB_VERSION_MINOR >= 3
		#else
			#error ""
		#endif
	#endif
#else
	#error ""
#endif
'''

def CheckBDB(context):
	context.Message("Checking for BDB >= 4.3...")
	ret = context.TryCompile(bdb_source, '.c')
	context.Result(ret)
	return ret
