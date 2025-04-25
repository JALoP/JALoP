#!/bin/python3
import os
import datetime
import sys

data = ""
with open('test_file.db', 'r') as f:
    data = f.read()

x = datetime.datetime.now()

for i in range(30000):
    z = datetime.datetime.now().timestamp()
    with open('file_system_test/' + str(z), 'w') as file:
        file.write(data)
        #file.close()

y = datetime.datetime.now()
print(y.timestamp() - x.timestamp())

x = datetime.datetime.now()
command = "scp file_system_test/* dlinsalata@192.168.1.199:~/jalop_home/file_system_test>/dev/null"
os.system(command)
y = datetime.datetime.now()

print(y.timestamp() - x.timestamp())
