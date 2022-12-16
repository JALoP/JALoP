#!/usr/bin/python

import os
import sys

dir = os.getcwd()
path = dir + "/" + sys.argv[1]
print (path)

sfile = open(path, "r")
lines = sfile.readlines()
sfile.close()
init_syscalls = set()
final_syscalls = set()
Z_found = 0
for line in lines :
    if line.find("SECCOMP_PROCESS_IS_DONE_SETTING_UP")>0:
        Z_found = 1
        continue
    space = line.find(" ") + 1
    leftp = line.find("(")
    if leftp>0 :        
        call = line[space : leftp]
        if call[0] >= 'a' and call[0] <= 'z':
            if Z_found==0:
                init_syscalls.add(call)
            else:
                final_syscalls.add(call)

print ("INIT " + " " + str(len(init_syscalls)))

print ("FINAL "  + " " + str(len(final_syscalls)))

both_syscalls = init_syscalls.intersection(final_syscalls)

total_syscalls = init_syscalls.union(final_syscalls)

init_syscalls.difference_update(both_syscalls)
final_syscalls.difference_update(both_syscalls)

init = sorted(init_syscalls)
both = sorted(both_syscalls)
final = sorted(final_syscalls)
init_cfg = "initial_seccomp_rules = ["
both_cfg = "both_seccomp_rules = ["
final_cfg = "final_seccomp_rules = ["

print ("TOTAL " + str(len(total_syscalls))) 
count = 0;
for call in init:
    if count>0:
        init_cfg = init_cfg + ",\"" + call + "\""
    else: 
        init_cfg = init_cfg + "\"" + call + "\""
    count = count + 1
init_cfg = init_cfg + "]"
print ("INIT ONLY " + str(len(init_syscalls))) 
print (init_cfg)

count = 0
for call in both:
    if count>0:
        both_cfg = both_cfg + ",\"" + call + "\"" 
    else:
        both_cfg = both_cfg + "\"" + call + "\"" 
    count = count + 1
both_cfg = both_cfg + "]"
print ("BOTH " + str(len(both_syscalls))) 
print (both_cfg)

count = 0
for call in final:
    if count>0:
        final_cfg = final_cfg + ",\"" + call + "\"" 
    else:
        final_cfg = final_cfg + "\"" + call + "\"" 
    count = count + 1
final_cfg = final_cfg + "]"
print ("FINAL ONLY " + str(len(final_syscalls))) 
print (final_cfg)

