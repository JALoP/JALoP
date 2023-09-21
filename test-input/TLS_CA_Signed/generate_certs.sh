#!/bin/bash
PASSWORD=changeit
SHA_VERSION=-sha384
AES_VERSION=-aes256
CLIENT_NAME=jal_publisher_v2_client
SERVER_NAME=jal_subscriber_v2_server

rm -fr server client
################################################################################
#Create CA Key Pair
openssl genrsa $AES_VERSION -passout pass:$PASSWORD -out jalop_ca.key.pem 4096 

#Create CA Public Certificate
openssl req -config ca.cnf -batch -passin pass:$PASSWORD \
	-key jalop_ca.key.pem -new -x509 -days 7300 $SHA_VERSION \
	-extensions v3_ca -out jalop_ca.cert.pem

################################################################################
## Create Server Key Pair
openssl genrsa $AES_VERSION -passout pass:$PASSWORD -out $SERVER_NAME.key.pem 2048
## Decrypt and remove password
openssl rsa -passin pass:$PASSWORD -in $SERVER_NAME.key.pem -out $SERVER_NAME.key.pem 

## Create server signing request
openssl req -new -config server.cnf -batch $SHA_VERSION \
	-key $SERVER_NAME.key.pem  \
	-out $SERVER_NAME.csr.pem

## Sign server certificate
openssl x509 -req \
	-days 3650 -passin pass:$PASSWORD \
	-in $SERVER_NAME.csr.pem $SHA_VERSION \
	-CA jalop_ca.cert.pem \
	-CAkey jalop_ca.key.pem \
	-CAcreateserial \
	-extfile server.cnf \
	-extensions server_req \
	-out $SERVER_NAME.cert.pem
################################################################################
## Create Client Key Pair
openssl genrsa $AES_VERSION -passout pass:$PASSWORD -out $CLIENT_NAME.key.pem 2048
## Decrypt and remove password
openssl rsa -passin pass:$PASSWORD -in $CLIENT_NAME.key.pem -out $CLIENT_NAME.key.pem 

## Create client signing request
openssl req -new -config client.cnf -batch $SHA_VERSION \
	-key $CLIENT_NAME.key.pem  \
	-out $CLIENT_NAME.csr.pem

## Sign client certificate
openssl x509 -req \
	-days 3650 -passin pass:$PASSWORD \
	-in $CLIENT_NAME.csr.pem $SHA_VERSION \
	-CA jalop_ca.cert.pem \
	-CAkey jalop_ca.key.pem \
	-CAcreateserial \
	-extfile client.cnf \
	-extensions client_req \
	-out $CLIENT_NAME.cert.pem
################################################################################
rm -fr server client
mkdir server client
mkdir server/trust_store_dir client/trust_store_dir
cp $CLIENT_NAME.key.pem client
cp $CLIENT_NAME.cert.pem client
cp jalop_ca.cert.pem client/trust_store_dir
cp $SERVER_NAME.cert.pem client/trust_store_dir
#cat jalop_ca.cert.pem > client/$CLIENT_NAME.trusted_certs
#cat $SERVER_NAME.cert.pem >> client/$CLIENT_NAME.trusted_certs
ln client/trust_store_dir/$SERVER_NAME.cert.pem client/trust_store_dir/$(openssl x509 -noout -hash -in client/trust_store_dir/$SERVER_NAME.cert.pem).0
ln client/trust_store_dir/jalop_ca.cert.pem client/trust_store_dir/$(openssl x509 -noout -hash -in client/trust_store_dir/jalop_ca.cert.pem).0

cp $SERVER_NAME.key.pem server
cp $SERVER_NAME.cert.pem server
cp jalop_ca.cert.pem server/trust_store_dir
cp $CLIENT_NAME.cert.pem server/trust_store_dir
cat jalop_ca.cert.pem > server/trust_store_dir/$SERVER_NAME.trusted_certs
cat $CLIENT_NAME.cert.pem >> server/trust_store_dir/$SERVER_NAME.trusted_certs
ln server/trust_store_dir/$CLIENT_NAME.cert.pem server/trust_store_dir/$(openssl x509 -noout -hash -in server/trust_store_dir/$CLIENT_NAME.cert.pem).0
ln server/trust_store_dir/jalop_ca.cert.pem server/trust_store_dir/$(openssl x509 -noout -hash -in server/trust_store_dir/jalop_ca.cert.pem).0

rm -f $SERVER_NAME.*; 
rm -f $CLIENT_NAME.*; 
rm -f jalop_ca.*

./generate_java_keystore.sh
