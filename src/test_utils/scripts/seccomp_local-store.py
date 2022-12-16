#!/usr/bin/python

import os

dir = os.getcwd()

os.system("killall ./release/bin/jal-local-store 2>/dev/null")

os.system("rm -fr testdb/* 2>/dev/null")

os.system("rm -f jal.sock 2>/dev/null")

ret = os.system("./release/bin/jal-local-store -d -c ./test-input/local_store.cfg 1>/dev/null")
if (ret !=0):
    print ("jal-local-store failed to start")
    quit()

ret = os.system("echo 'hello world'|./release/bin/jalp_test -j ./jal.sock -s -n 2 -t l 1>/dev/null")
if (ret !=0):
    print ("jalp_test failed sending logs")
    quit()
print ("Logs:")
print os.system("./release/bin/jaldb_tail -h ./testdb -t l -d p |grep  '=>' ")

ret = os.system("echo 'hello world'|./release/bin/jalp_test -j ./jal.sock -s -n 2 -t j 1>/dev/null")
if (ret !=0):
    print ("jalp_test failed sending journals")
    quit()
print ("Journals;")
print os.system("./release/bin/jaldb_tail -h ./testdb -t j -d p |grep '=>'")

ret = os.system("./release/bin/jalp_test -j ./jal.sock -a ./test-input/sample2.cfg -p ./test-input/big_payload.txt -n 2 -t a 1>/dev/null")
if (ret !=0):
    print ("jalp_test failed sending audits")
    quit()
print ("Audits;")
print os.system("./release/bin/jaldb_tail -h ./testdb -t a -d p |grep '=>'")

command = "ps aux|grep " + os.getlogin()[0:5] + "|grep jal-local-store|grep -v grep "

print ("Process Running:")
ret = os.system(command)
if (ret !=0):
    print ("jal-local-store failed finding process")
    quit()
print ret

ret = os.system("killall ./release/bin/jal-local-store")
print ("Process Killed:")
os.system(command)
if (ret !=0):
    print ("jal-local-store failed killing process")
    quit()

#To view SECCOMP failures
#cat /var/log/audit/audit|grep SECCOMP    // as root

#To run your process with strace
#strace -f -o strace.out ./release/bin/jal-local-store -d -c ./test-input/local_store.cfg
#cat strace.out | sed 's/^[0-9]* //' | sed 's/).*$/)/'|sort|uniq  //to include params
#cat strace.out | sed 's/^[0-9]* //' | sed 's/(.*$//'|sort|uniq  //to exclude params
