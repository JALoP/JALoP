#!/usr/local/bin/python3
import os
import subprocess

from pathlib import Path

extension_list = [ '.spec' ]
rpm_dir = str(Path(os.getcwd()).parents[2]) + os.sep + 'RPM'

# Walk through the current directory, recusively
# dirnames - directory children of the current folder
# filenames - file children of the current folder
spec_files = [f for f in os.listdir(rpm_dir) if os.path.isfile(rpm_dir + os.sep + f)]
for filename in spec_files:
    _, extension = os.path.splitext(filename)
    abs_path = os.path.join(rpm_dir, filename)

    # If this is an extension we are looking for
    if extension in extension_list:
      # Not strictly necessary to print, but we see no output when rpmlint
      # produces no warnings/errors - better to at least see an indication that it ran
      print('Running rpmlint on: {}'.format(abs_path))
      subprocess.run(['rpmlint', abs_path])
