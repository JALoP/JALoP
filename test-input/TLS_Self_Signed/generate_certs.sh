#!/bin/bash
rm -rf pub-certs sub-certs

#Generate Publisher key & certificate -
mkdir -p pub-certs/trust_store_dir
cd pub-certs/ || exit
openssl genrsa -out publisher.key 2048
#  [Change the IP address in the client.cnf to the IP address of the publisher]
openssl req -new -key publisher.key -out pub.csr -config ../client.cnf  -subj "/C=US/ST=MD/L=Savage/O=publisher/CN=publisher"
openssl x509 -req -days 730 -in pub.csr -signkey publisher.key -out publisher.crt -extfile ../client.cnf -extensions client_req

cd ../ || exit

#Generate Subscriber key & certificate -
mkdir -p sub-certs/trust_store_dir
cd sub-certs/ || exit
openssl genrsa -out subscriber.key 2048
#  [Change the IP address in the server.cnf file to the IP address of the subscriber]
openssl req -new -key subscriber.key -out sub.csr -config ../server.cnf -subj "/C=US/ST=MD/L=Savage/O=subscriber/CN=subscriber"
openssl x509 -req -days 730 -in sub.csr -signkey subscriber.key -out subscriber.crt -extfile ../server.cnf -extensions server_req

cd ../ || exit

#The public certificate of peers must be stored in the format below -
#<subject hash>.<index>

#Create links to the certificates in the proper format -
cp -f sub-certs/subscriber.crt pub-certs/trust_store_dir/subscriber.crt
cp -f pub-certs/publisher.crt sub-certs/trust_store_dir/publisher.crt
ln pub-certs/trust_store_dir/subscriber.crt pub-certs/trust_store_dir/"$(openssl x509 -noout -hash -in pub-certs/trust_store_dir/subscriber.crt)".0
ln sub-certs/trust_store_dir/publisher.crt sub-certs/trust_store_dir/"$(openssl x509 -noout -hash -in sub-certs/trust_store_dir/publisher.crt)".0
cat pub-certs/publisher.crt >> sub-certs/trust_store_dir/publisher.trusted_certs

./generate_java_keystore.sh
