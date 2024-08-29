#!/bin/bash
STOREPASS=changeit
PASSWORD=changeit
CLIENT_NAME=jal_subscriber_v1_client
SERVER_NAME=jal_publisher_v1_server

rm -f sub-certs/$CLIENT_NAME-remotes.jks sub-certs/$CLIENT_NAME.pem sub-certs/$CLIENT_NAME.jks
rm -f pub-certs/$SERVER_NAME-remotes.jks pub-certs/$SERVER_NAME.pem pub-certs/$SERVER_NAME.jks

#generates publisher keystores
keytool -genkeypair -keyalg rsa -keystore pub-certs/$SERVER_NAME.jks -noprompt -storepass $STOREPASS -keypass $STOREPASS -dname "CN=publisher, OU=ID,O=test, L=test, S=MD, C=US" -alias server

#export public publisher cert
keytool -exportcert -rfc -keystore pub-certs/$SERVER_NAME.jks -noprompt -storepass $STOREPASS -alias server > pub-certs/$SERVER_NAME.pem

#generate subscriber keystore
keytool -genkeypair -keyalg rsa -keystore sub-certs/$CLIENT_NAME.jks -noprompt -storepass $STOREPASS -keypass $STOREPASS -dname "CN=subscriber, OU=ID,O=test, L=test, S=MD, C=US" -alias client

#export public publisher cert
keytool -exportcert -rfc -keystore sub-certs/$CLIENT_NAME.jks -noprompt -storepass $STOREPASS -alias client > sub-certs/$CLIENT_NAME.pem

#Import certs into subscriber truststore
keytool -importcert -keystore sub-certs/$CLIENT_NAME-remotes.jks -storepass $STOREPASS \
	-file pub-certs/$SERVER_NAME.pem -alias jjnl_publisher -noprompt

keytool -importcert -keystore sub-certs/$CLIENT_NAME-remotes.jks -storepass $STOREPASS \
	-file sub-certs/$CLIENT_NAME.pem -alias jjnl_subscriber -noprompt

keytool -importcert -keystore sub-certs/$CLIENT_NAME-remotes.jks -storepass $STOREPASS \
	-file sub-certs/subscriber.crt -alias jal_subscriber -noprompt

keytool -importcert -keystore sub-certs/$CLIENT_NAME-remotes.jks -storepass $STOREPASS \
	-file pub-certs/publisher.crt -alias jald_publisher -noprompt

#Import certs into publisher truststore
keytool -importcert -keystore pub-certs/$SERVER_NAME-remotes.jks -storepass $STOREPASS \
	-file pub-certs/$SERVER_NAME.pem -alias jjnl_publisher -noprompt

keytool -importcert -keystore pub-certs/$SERVER_NAME-remotes.jks -storepass $STOREPASS \
	-file sub-certs/$CLIENT_NAME.pem -alias jjnl_subscriber -noprompt

keytool -importcert -keystore pub-certs/$SERVER_NAME-remotes.jks -storepass $STOREPASS \
	-file sub-certs/subscriber.crt -alias jal_subscriber -noprompt

keytool -importcert -keystore pub-certs/$SERVER_NAME-remotes.jks -storepass $STOREPASS \
	-file pub-certs/publisher.crt -alias jald_publisher -noprompt

#Creates link to jjnl certs for jald/jal_subscriber
mkdir -p pub-certs/trust_store_dir/
mkdir -p sub-certs/trust_store_dir/
cp -f sub-certs/$CLIENT_NAME.pem pub-certs/trust_store_dir/$CLIENT_NAME.pem
cp -f pub-certs/$SERVER_NAME.pem sub-certs/trust_store_dir/$SERVER_NAME.pem
ln sub-certs/trust_store_dir/$SERVER_NAME.pem sub-certs/trust_store_dir/"$(openssl x509 -noout -hash -in sub-certs/trust_store_dir/$SERVER_NAME.pem)".0
ln pub-certs/trust_store_dir/$CLIENT_NAME.pem pub-certs/trust_store_dir/"$(openssl x509 -noout -hash -in pub-certs/trust_store_dir/$CLIENT_NAME.pem)".0