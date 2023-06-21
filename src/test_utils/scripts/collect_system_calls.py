#!/usr/bin/python

import os
import sys

if len(sys.argv) < 2:
	print ("You need to specify an strace output file.")
	exit()

dir = os.getcwd()
path = dir + "/" + sys.argv[1]
print (path)

if not os.path.exists(path):
	print ("Bad file location")
	exit()

sfile = open(path, "r")

lines = sfile.readlines()
sfile.close()

init_syscalls = set()
final_syscalls = set()
break_point_found = 0
for line in lines :
    if line.find("SECCOMP_PROCESS_IS_DONE_SETTING_UP")>0:
        break_point_found = 1
        continue
    space = line.find(" ") + 1
    leftp = line.find("(")
    if leftp>0 :        
        call = line[space : leftp]
        if call[0] >= 'a' and call[0] <= 'z':
            if break_point_found==0:
                init_syscalls.add(call)
            else:
                final_syscalls.add(call)

print("---------------------------")
print("INIT " + " " + str(len(init_syscalls)))
print("FINAL "  + " " + str(len(final_syscalls)))
total = len(init_syscalls) + len(final_syscalls)
print("TOTAL " + " " + str(total) )
print("---------------------------")

#find calls that are both in init and final sets
both_syscalls = init_syscalls.intersection(final_syscalls)

#extract out calls from init_syscalls that are in both_syscalls
init_syscalls.difference_update(both_syscalls)

#extract out calls from final_syscalls that are in both_syscalls
final_syscalls.difference_update(both_syscalls)

print("---------------------------")
print("INIT ONLY " + str(len(init_syscalls))) 
print("BOTH " + str(len(both_syscalls))) 
print("FINAL ONLY " + str(len(final_syscalls))) 
print("---------------------------")

#print out init_syscalls in an array
init = sorted(init_syscalls)
init_cfg = "initial_seccomp_rules = ["
count = 0;
for call in init:
    if count>0:
        init_cfg = init_cfg + ",\"" + call + "\""
    else: 
        init_cfg = init_cfg + "\"" + call + "\""
    count = count + 1
init_cfg = init_cfg + "]"
print (init_cfg)

#print out both_syscalls in an array
both = sorted(both_syscalls)
both_cfg = "both_seccomp_rules = ["
count = 0
for call in both:
    if count>0:
        both_cfg = both_cfg + ",\"" + call + "\"" 
    else:
        both_cfg = both_cfg + "\"" + call + "\"" 
    count = count + 1
both_cfg = both_cfg + "]"
print (both_cfg)

#print out final_syscalls in an array
final = sorted(final_syscalls)
final_cfg = "final_seccomp_rules = ["
count = 0
for call in final:
    if count>0:
        final_cfg = final_cfg + ",\"" + call + "\"" 
    else:
        final_cfg = final_cfg + "\"" + call + "\"" 
    count = count + 1
final_cfg = final_cfg + "]"
print (final_cfg)

print("---------------------------")
