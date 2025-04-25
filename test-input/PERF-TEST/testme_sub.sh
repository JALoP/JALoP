#!/bin/bash

SSH_USER_PUB="dlinsalata@192.168.1.199"
JALOP_HOME_PUB="/home/dlinsalata/jalop_home/jalopv2"

JALOP_HOME_PUB_SCRIPT=$JALOP_HOME_PUB/"test-input/PERF-TEST/testme_pub.sh"
JALOP_HOME_PUB_BIN=$JALOP_HOME_PUB/"release/bin/*"
EXPORT="export LD_LIBRARY_PATH=$JALOP_HOME_PUB/release/lib"
export LD_LIBRARY_PATH=./release/lib

readarray configs < $1
start_seconds=$(date +%s)
for test in "${configs[@]}"
do
	if [[ ${test:0:1} == "#" ]]; then
		echo "Excluding: $test"
		continue
	fi
	read -ra vars <<< "${test[@]}"
	for var in "${vars[@]}"
	do
		declare "${var}"	
		#echo "sub ${var}"
	done
	tar -cf ../TARS/test-backup.tar ./test-input
	if [ $proto == "http-c" ] || [ $proto == "http-j" ]; then
		tar -xf ../TARS/test-input-v2.tar ./test-input
		if [ $db == "lmdb" ]; then
			tar -xf ../TARS/httpv2-lmdb.tar ./release
		else
			tar -xf ../TARS/httpv2-bdb.tar ./release
		fi
	else
		tar -xf ../TARS/test-input-v1.tar ./test-input
		if [ $db == "lmdb" ]; then
			tar -xf ../TARS/beepv1-lmdb.tar ./release
		else
			tar -xf ../TARS/beepv1-bdb.tar ./release
		fi
	fi
	export LD_LIBRARY_PATH=./release/lib

	killall -9 ./release/bin/jal_subscribe >/dev/null 2>&1
	#ps ax|grep JJ|grep -v grep|awk '{print $1}'
	rm -fr ./subdb/*

	sed -i "s/^window_size.*$/window_size = $window_size;/g" test-input/jal_subscribe.cfg 
	sed -i "s/^database_option =.*$/database_option = \"JDB_LMDB_PERFORMANCE_LEVEL$level\";/g" test-input/jal_subscribe.cfg
	sed -i "s/^pending_digest_max =.*$/pending_digest_max = ${batch}L;/g" test-input/jal_subscribe.cfg
	sed -i "s/^enable_seccomp.*$/enable_seccomp = ${seccomp};/g" test-input/jal_subscribe.cfg
	if [[ $proto == beep-j ]]; then
		sed -i "s/\"configureTLS\".*$/\"configureTLS\": \"${tls}\",/g" ./test-input/PERF-TEST/JJNL/beepSubscriber.json
		java -jar ./test-input/PERF-TEST/JJNL/jnl_beep.jar ./test-input/PERF-TEST/JJNL/beepSubscriber.json >java.log 2>&1 &
	else
		if [[ $proto == http-j ]]; then
			sed -i "s/\"configureTLS\".*$/\"configureTls\": \"${tls}\",/g" ./test-input/PERF-TEST/JJNL/httpSubscriber.json
			java -jar ./test-input/PERF-TEST/JJNL/jnl_http.jar ./test-input/PERF-TEST/JJNL/httpSubscriber.json >java.log 2>&1 &
		else
			if [[ $tls == "on" ]]; then
				./release/bin/jal_subscribe -c test-input/jal_subscribe.cfg  >/dev/null 2>&1 &
			else
				./release/bin/jal_subscribe -c test-input/jal_subscribe.cfg -s  >/dev/null 2>&1 &
			fi
		fi
	fi

	sleep 2

	ssh -t $SSH_USER_PUB "cd $JALOP_HOME_PUB;$EXPORT;$JALOP_HOME_PUB_SCRIPT ${vars[@]}"
	middle_seconds=$(date +%s)

	PROCESS="jal_subscribe"
	PID=`/usr/sbin/pidof $PROCESS`
	if [[ $proto == beep-j ]] || [[ $proto == http-j ]]; then
		PROCESS="java"
		PID=`ps ax|grep -P -m 1 "JJNL" |awk '{print $1}'`
	fi
	
	(( cpu="10" ))
	(( retry_count=0 ))
	while [ $cpu != "0.0" ]
	do
		sleep 1
		cpu=`top -b -n 1 -p $PID | grep -P -m 7 $PID | awk '{print $9}'`
		if [[ $cpu == "0.0" ]] && [[ $retry_count < 5 ]]; then
			(( cpu="10" ))
			(( retry_count=$retry_count + 1 ))
		else
			(( retry_count=0 ))
		fi
	done

	end_seconds=$(date +%s)

	sleep 2

	tool_command="./release/bin/jaldb_tool -h testdb/ -t z -s"
	pub_tool=`ssh -t $SSH_USER_PUB "cd $JALOP_HOME_PUB;$EXPORT;$tool_command"`
	t2_1=`grep Total <<< "$pub_tool"`
	t2_2=`sed  's/Total Time //g' <<< $t2_1`
	t2_3=`echo "$t2_2"|tr -d '[:space:]'`
	
	lineJ=`grep journal <<< "$pub_tool"`
	syncJ=`awk '{print $5}' <<< $lineJ`
	lineA=`grep audit <<< "$pub_tool"`
	syncA=`awk '{print $5}' <<< $lineA`
	lineL=`grep log <<< "$pub_tool"`
	syncL=`awk '{print $5}' <<< $lineL`

	error_message=""
	(( total_synced=$syncJ + $syncA + $syncL ))
	(( total_expected=$count*3 ))
	if [[ $total_synced != $total_expected ]]; then
		error_message="FAILED SYNCED=$total_synced "
	fi
	
	if [[ $proto == beep-j ]] || [[ $proto == http-j ]]; then
		IFS=':' read -ra HMS <<< $t2_3
		(( insert_seconds=(${HMS[0]}*3600)+(${HMS[1]}*60)+${HMS[2]} ))
		(( t1_3=($end_seconds-$middle_seconds)+$insert_seconds ))
	else
		tool=`./release/bin/jaldb_tool -h subdb/ -t z -s`
		t1_1=`grep Total <<< "$tool"`
		t1_2=`sed  's/Total Time //g' <<< $t1_1`
		t1_3=`echo "$t1_2"|tr -d '[:space:]'`	
	fi

	date=$(date '+%Y-%m-%dT%H:%M:%S')
	 
	echo "date:$date ${vars[@]} iTime=$t2_3 tTime=$t1_3 ${error_message}"
	
	kill -9 $PID >/dev/null 2>&1
	ssh -t $SSH_USER_PUB "killall -9 $JALOP_HOME_PUB_BIN >/dev/null 2>&1"
	#tar -xf ../TARS/test-backup.tar ./test-input
done
