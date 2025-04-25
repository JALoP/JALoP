#!/bin/bash

RECS=10
#PAYLOAD="test-input/big_payload.txt"
PAYLOAD="test-input/good_audit_input.xml"

start=$(date +%s)

./release/bin/jalp_test -j jal.sock -a ./test-input/sample4.cfg -p $PAYLOAD -n $RECS -t j

./release/bin/jalp_test -j jal.sock -a ./test-input/sample4.cfg -p $PAYLOAD -n $RECS -t a

./release/bin/jalp_test -j jal.sock -a ./test-input/sample4.cfg -p $PAYLOAD -n $RECS -t l

PROCESS="jald"
PID=`pidof $PROCESS`
echo $PID
cpu=`top -b -n 1 -d 0.2 -p $PID | grep $PROCESS |awk '{print $9}'`

while [ $cpu != "0.0" ]
do
	sleep 2
	cpu=`top -b -n 1 -p $PID | grep $PROCESS | awk '{print $9}'`
done

./release/bin/jaldb_tool -h testdb/ -t z -s

finish=$(date +%s)

(( total_time=$finish-$start ))

#echo $total_time

#watch top -b -n 2 -d 0.2 -p `pidof jald`
