#!/usr/bin/python
import os
import sys
from pathlib import Path
import xml.etree.ElementTree as ET
from datetime import datetime

seccomp_out_dir = sys.argv[1]

now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
command = "echo '" + now + "' > my_rules.txt"
os.system(command)
seccomp_out_files = [f for f in os.listdir(seccomp_out_dir) if os.path.isfile(seccomp_out_dir + os.sep + f)]
for filename in seccomp_out_files:
    out_path = os.path.join(seccomp_out_dir, filename)
    name, extension = os.path.splitext(filename)
    if (extension == ".out"):
        print("create:" + out_path)
        command = "./src/test_utils/scripts/seccomp/collect_system_calls_from_script.py " + out_path + " >> " + seccomp_out_dir + "/" + name + ".cfg"
        os.system(command)

