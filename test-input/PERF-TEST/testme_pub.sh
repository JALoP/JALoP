#!/bin/bash

read -ra vars <<< "$@"
for var in "${vars[@]}"
do
	declare "${var}"	
	#echo "pub ${var}"
done

killall -9 ./release/bin/jal-local-store >/dev/null 2>&1
killall -9 ./release/bin/jald >/dev/null 2>&1
rm -fr testdb/*
rm -f jal.sock
./release/bin/jal-local-store -c ./test-input/local_store.cfg >/dev/null 2>&1 &
sleep 2
if [[ $tls == "on" ]]; then
	./release/bin/jald -c ./test-input/jald.cfg >/dev/null 2>&1
else
	./release/bin/jald -c ./test-input/jald.cfg -s >/dev/null 2>&1
fi
sleep 2

if [[ $payload_size == 32 ]]; then
        PAYLOAD="test-input/big_payload.txt"
else
        PAYLOAD="test-input/good_audit_input.xml"
fi

sed -i "s/^database_option =.*$/database_option = \"JDB_LMDB_PERFORMANCE_LEVEL$level\";/g" test-input/jald.cfg
sed -i "s/^database_option =.*$/database_option = \"JDB_LMDB_PERFORMANCE_LEVEL$level\";/g" test-input/local_store.cfg
sed -i "s/^enable_seccomp.*$/enable_seccomp = ${seccomp};/g" test-input/jald.cfg
sed -i "s/^enable_seccomp.*$/enable_seccomp = ${seccomp};/g" test-input/local_store.cfg

./release/bin/jalp_test -j jal.sock -a ./test-input/sample4.cfg -p $PAYLOAD -n ${count} -t j

./release/bin/jalp_test -j jal.sock -a ./test-input/sample4.cfg -p $PAYLOAD -n ${count} -t a

./release/bin/jalp_test -j jal.sock -a ./test-input/sample4.cfg -p $PAYLOAD -n ${count} -t l

PROCESS="jal-local-store"
PROCESS_NAME="./release/bin/jal-local-store"
PID=`/usr/sbin/pidof $PROCESS`
cpu=`top -b -n 1 -d 0.2 -p $PID | grep -P -m 7 $PID |awk '{print $9}'`

while [  $cpu != "0.0" ]
do
        sleep 1
        cpu=`top -b -n 1 -p $PID | grep $PID | awk '{print $9}'`

done
