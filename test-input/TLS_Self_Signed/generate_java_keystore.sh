#!/bin/bash
STOREPASS=changeit
PASSWORD=changeit
SUB_NAME=jal_subscriber_v2_server
SHA_VERSION=SHA384withRSA

rm -f sub-certs/$SUB_NAME-remotes.jks sub-certs/$SUB_NAME.pem sub-certs/$SUB_NAME.jks

#generate subscriber keystore
#change the IP address to the IP address of subscriber.
keytool -genkeypair -keyalg rsa -keystore sub-certs/$SUB_NAME.jks -noprompt -storepass $STOREPASS -keypass $STOREPASS -dname "CN=subscriber, OU=ID,O=test, L=test, S=MD, C=US" \
        -alias server -sigalg $SHA_VERSION -dname "CN=127.0.0.1" -ext "SAN=IP:127.0.0.1"

#export public publisher cert
keytool -exportcert -rfc -keystore sub-certs/$SUB_NAME.jks -noprompt -storepass $STOREPASS -alias server > sub-certs/$SUB_NAME.pem

#Import certs into subscriber truststore
keytool -importcert -keystore sub-certs/$SUB_NAME-remotes.jks -storepass $STOREPASS \
	-file pub-certs/publisher.crt -alias jald_publisher -noprompt

#Creates link to jjnl certs for jald/jal_subscriber
mkdir -p sub-certs/trust_store_dir/
cp -f sub-certs/$SUB_NAME.pem pub-certs/trust_store_dir/$SUB_NAME.pem
ln pub-certs/trust_store_dir/$SUB_NAME.pem pub-certs/trust_store_dir/"$(openssl x509 -noout -hash -in pub-certs/trust_store_dir/$SUB_NAME.pem)".0