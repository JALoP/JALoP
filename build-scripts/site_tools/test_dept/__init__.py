import SCons.Builder
import string
import os
import subprocess

platform = subprocess.Popen(['uname', '-p'], stdout=subprocess.PIPE).communicate()[0].decode('ascii').strip()

if platform == 'i686' or platform == 'i386':
	SYMBOLS_TO_ASM = 'sym2asm_i686.awk'
elif platform == 'x86_64':
	SYMBOLS_TO_ASM = 'sym2asm_x86_64.awk'

def TestDeptMainFromSymbols(source, target, env, for_signature):
	''' This will take a test_depth style driver program and generate a
	    test_dept main program. Basically, the build_main_from_symbols
	    script considers any function starting with the string 'test_' to
	    be a test case and generates the apropriate C code. See test_dept
	    for more info.

	    source must C source file that contains all the unit tests.

	    target will get overwritten with a 'main()' function that calls
	    each unit test from 'source'
	'''
	return 'nm -p %s | build_main_from_symbols > %s' % (source[0], target[0])

def TestDeptReplacementSymbols(source, target, env, for_signature):
	''' This scans the source file defined symbols and writes out a simple
	text file that has the original, and proxyied symbol names. This will
	get fed into TestDeptObjectCopyReplacingSymbols to do the symbol
	replacement. It generates a file like this:

	printf printf_test_dept_proxy
	malloc malloc_test_dept_proxy


	The first column is the symbol defined in the object file, the second
	is the proxied symbol.
	'''
	return 'nm -p %s | sym2repl > %s' % (source[0], target[0])

def TestDeptProxies(source, target, env, for_signature):
	''' This builds out the magic of test_dept. It takes the object files
	for the unit test driver, and generated main function and 
	files, and generates an assembly file that proxies all the function
	calls'''
	return 'sym2asm %s %s %s nm > %s' % (source[0], source[1], SYMBOLS_TO_ASM, target[0])

def TestDeptObjectCopyReplacingSymbols(source, target, env, for_signature):
	''' Takes 2 imput sources, the first is an object file, and the second
	is a text file that lists the symbols to replace. The input file
	should look like this:

	printf printf_test_dept_proxy
	malloc malloc_test_dept_proxy

	The first column is the symbol defined in the object file, the second
	is the proxied symbol.
	'''
	return 'objcopy_wrapper objcopy %s %s %s' % (source[0], source[1], target[0])

def TestDeptTest(env, testfile, other_sources, useProxies=False):
	''' This function hooks everything together.

	testfile should be a file named test_<sut>.c, where <sut> is the
	filename of the object file we are testing. For example, to test the
	object file generated from foo.c, the unit test driver should be name
	test_foo.c

	other_sources is an array of additional targets to link against.

	In addition to the source file test_<sut>.c, this expects there to be a
	test_<sut>_no_proxy.txt file. It uses this file to prevent adding code
	to proxy various functions. At a minimun, this file must have the
	functions being tested listed. For example, if the unit tests are
	getting written for a function named foobar(), the
	test_<sut>_no_proxy.txt file should have a line like the following:

	foobar_test_dept_proxy foobar
	'''

	sut_suffix = env['SHOBJSUFFIX']
	sut_prefix = env['SHOBJPREFIX']
	# On solaris, SHOBJPREX is so_, but on linux and others it
	# gets defined as $OBJPREFIX. 
	# TODO: Find a better way to resolve the variable.
	if sut_prefix[0] == '$':
		sut_prefix = env[sut_prefix.split('$')[1]]

	c_suffix = env['CFILESUFFIX']
	(sut, suffix) = str(testfile).split('test_')[1].rsplit('.')
	sut_path = os.path.join('..', 'src')
	sut_object = os.path.join(sut_path, sut_prefix + sut + sut_suffix)

	proxies = 'test_' + sut + '_proxies.s'
	sut_using_proxies = sut_prefix + 'test_' + sut + '_using_proxies' + sut_suffix
	sut_using_proxies_tmp = sut_prefix + 'test_' + sut + '_using_proxies.tmp' + sut_suffix
	protected_symbols = 'test_' + sut + '_no_proxy.txt'
	replacement_symbols = 'test_' + sut + '_replacement_symbols.txt'
	test_main = 'main_test_' + sut + c_suffix

	test_object = env.SharedObject(source=testfile)
	test_main = env.TDMainFromSymbols(target=[test_main], source=[test_object])
	test_main_object = env.SharedObject(test_main)
	test_sources = [test_object, test_main_object]
	# not going to try and proxy calls to C++ code
	if useProxies and (suffix == 'c'):
		t = env.TDReplacementSymbols(target=replacement_symbols, source=test_object)
		env.TDProxies(target=proxies, source=[test_object, test_main_object])
		proxiesObject = env.SharedObject(proxies)
		env.TDObjectCopyReplacingSymbols(target=sut_using_proxies_tmp, source=[replacement_symbols, sut_object])
		env.TDObjectCopyReplacingSymbols(target=sut_using_proxies, source=[protected_symbols, sut_using_proxies_tmp])
		test_sources.append(sut_using_proxies)
		test_sources.append(proxiesObject)
	else:
		test_sources.append(sut_object)

	for i in other_sources:
		test_sources.append(i);

	test = env.Program(target='main_test_' + sut, source=test_sources)
	return test

def generate(env):
	'''SCons looks for this function to add the tool to the environment'''
	env.AddMethod(TestDeptTest)
	env.Append(BUILDERS = { 'TDMainFromSymbols' :  SCons.Builder.Builder(generator=TestDeptMainFromSymbols),
				'TDReplacementSymbols': SCons.Builder.Builder(generator=TestDeptReplacementSymbols),
				'TDProxies': SCons.Builder.Builder(generator=TestDeptProxies),
				'TDObjectCopyReplacingSymbols': SCons.Builder.Builder(generator=TestDeptObjectCopyReplacingSymbols) })
	env.AppendUnique(TEST_DEPT = 'test-dept')

def exists(env):
	''' Required by SCons, checks to see if test_dept installed'''
	return env.Detect("test_dept")

