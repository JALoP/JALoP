#!/usr/local/bin/python3
import os
import magic # Must be installed - `pip3 install python-magic`
import subprocess

from pathlib import Path

mime = magic.Magic(mime=True)
mime_dict = {}
script_mime_list = [ 'text/x-shellscript' ]

# Walk through the current directory, recusively
# dirpath - absolute path to the current folder
# dirnames - directory children of the current folder
# filenames - file children of the current folder
for dirpath, dirnames, filenames in os.walk(str(Path(os.getcwd()).parents[2])):
  # Ignore files under the .git folder. These are sample hook scripts
  if os.sep + '.git' + os.sep in dirpath:
    continue
  else:
    # Inspect each file
    for filename in filenames:
      fn = dirpath + os.sep + filename
      type = mime.from_file(fn)

      # If this is a mime type we are looking for
      if type in script_mime_list:
        # Not strictly necessary to print, but we see no output when shellcheck
        # produces no warnings/errors - better to at least see an indication that it ran
        print('Running shell check on: {}'.format(fn))
        subprocess.run(['shellcheck', fn])
