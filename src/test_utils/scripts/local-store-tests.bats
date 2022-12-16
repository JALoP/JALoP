#!/usr/bin/env bats

@test start jal-local-store {
	killall ./release/bin/jal-local-store || true
	rm -fr testdb/* || true
	rm -f jal.sock || true
        run ./release/bin/jal-local-store -d -c ./test-input/local_store.cfg
}

@test log test {
	run ./release/bin/jalp_test -j ./jal.sock -p ./test-input/big_payload.txt -n 2 -t l
	run ./release/bin/jaldb_tail -h ./testdb -t l -d p 
	#echo "${#lines[@]}" >&3
	[ "${#lines[@]}" = 1284 ]
}

@test journal test {
	run ./release/bin/jalp_test -j ./jal.sock -p ./test-input/big_payload.txt -n 2 -t j
	run ./release/bin/jaldb_tail -h ./testdb -t j -d p
	#echo "${#lines[@]}" >&3
	[ "${#lines[@]}" = 15 ]
}

@test audit test {
	run ./release/bin/jalp_test -j ./jal.sock -a ./test-input/sample2.cfg -p ./test-input/big_payload.txt -n 2 -t a
	run ./release/bin/jaldb_tail -h ./testdb -t a -d p 
	#echo "${#lines[@]}" >&3
	[ "${#lines[@]}" = 1284 ]
}
@test stop jal-local-store {
	run killall ./release/bin/jal-local-store 
	rm -fr testdb/* || true
	rm -f jal.sock || true
}
#To view SECCOMP failures
##cat /var/log/audit/audit|grep SECCOMP    // as root
#
##To run your process with strace
##strace -f -o strace.out ./release/bin/jal-local-store -d -c ./test-input/local_store.cfg
##cat strace.out | sed 's/^[0-9]* //' | sed 's/).*$/)/'|sort|uniq  //to include params
##cat strace.out | sed 's/^[0-9]* //' | sed 's/(.*$//'|sort|uniq  //to exclude params
