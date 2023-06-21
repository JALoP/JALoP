#!/bin/bash
STOREPASS=changeit
PASSWORD=changeit
CLIENT_NAME=jal_publisher_v2_client
SERVER_NAME=jal_subscriber_v2_server

rm -f client/$CLIENT_NAME-remotes.jks client/$CLIENT_NAME.p12 client/$CLIENT_NAME.jks

openssl pkcs12 -export -in client/$CLIENT_NAME.cert.pem -inkey client/$CLIENT_NAME.key.pem \
	-out client/$CLIENT_NAME.p12 -name client -passin pass:$PASSWORD -passout pass:$PASSWORD

keytool -importkeystore -deststorepass $PASSWORD -destkeypass $PASSWORD -destkeystore client/$CLIENT_NAME.jks -deststoretype pkcs12 \
	-srckeystore client/$CLIENT_NAME.p12 -srcstoretype PKCS12 -srcstorepass $PASSWORD -alias client

keytool -importcert -keystore client/$CLIENT_NAME-remotes.jks -storepass $STOREPASS \
	-file client/trust_store_dir/$SERVER_NAME.cert.pem -alias server -noprompt

keytool -importcert -keystore client/$CLIENT_NAME-remotes.jks -storepass $STOREPASS \
	-file client/trust_store_dir/jalop_ca.cert.pem -alias ca -noprompt

rm -f client/$CLIENT_NAME.p12

rm -f server/$SERVER_NAME-remotes.jks server/$SERVER_NAME.p12 server/$SERVER_NAME.jks

openssl pkcs12 -export -in server/$SERVER_NAME.cert.pem -inkey server/$SERVER_NAME.key.pem \
	-out server/$SERVER_NAME.p12 -name server -passin pass:$PASSWORD -passout pass:$PASSWORD

keytool -importkeystore -deststorepass $PASSWORD -destkeypass $PASSWORD -destkeystore server/$SERVER_NAME.jks -deststoretype pkcs12 \
	-srckeystore server/$SERVER_NAME.p12 -srcstoretype PKCS12 -srcstorepass $PASSWORD -alias server

keytool -importcert -keystore server/$SERVER_NAME-remotes.jks -storepass $STOREPASS \
	-file server/trust_store_dir/$CLIENT_NAME.cert.pem -alias client -noprompt

keytool -importcert -keystore server/$SERVER_NAME-remotes.jks -storepass $STOREPASS \
	-file server/trust_store_dir/jalop_ca.cert.pem -alias ca -noprompt

rm -f server/$SERVER_NAME.p12

#keytool -list -v -keystore client/jal_subscriber_v1.jks -storepass $STOREPASS

#keytool -delete -keystore client/jal_subscriber_v1.jks -storepass $STOREPASS -alias mykey
