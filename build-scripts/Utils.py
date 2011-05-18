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
