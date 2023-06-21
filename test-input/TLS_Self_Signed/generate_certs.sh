#!/bin/bash
PASSWORD=changeit
SHA_VERSION=SHA384withRSA

rm -fr server client *.pem *.jks
################################################################################
#Generate Publisher (jald) Keystore of PKCS12 type
keytool -genkeypair -keyalg RSA -keystore publisher.jks -noprompt -sigalg $SHA_VERSION \
	-storepass changeit -keypass changeit -alias pub_key -deststoretype pkcs12 \
	-validity 3650 -dname "CN=192.168.137.136" -ext "SAN=IP:192.168.137.136"

#Export Publisher (jald) Certificate in PEM format -
openssl pkcs12 -in publisher.jks -nokeys -out pub_cert.pem \
	-passin pass:$PASSWORD -passout pass:$PASSWORD

#Export Publisher (jald) Private Key in PEM format -
openssl pkcs12 -in publisher.jks -nodes -nocerts -out pub_key.pem \
	-passin pass:$PASSWORD -passout pass:$PASSWORD

#Subscriber (JJNL jnl_test) side:
#Generate JJNL Subscriber Keystore of PKCS12 type -
keytool -genkeypair -keyalg RSA -keystore keystore.jks -noprompt -sigalg $SHA_VERSION \
	-storepass changeit -keypass changeit -alias sub_key -deststoretype pkcs12 \
	-validity 3650 -dname "CN=127.0.0.1" -ext "SAN=IP:127.0.0.1"

#Import jald Publsiher Certificate (pub_cert.pem) into JJNL Susbcriber Keystore -
keytool -importcert -keystore keystore.jks -file pub_cert.pem \
	-storepass changeit -keypass changeit -noprompt -alias "pub_key"

#Export JJNL Subscriber Certificate (PEM) from Keystore -
keytool -exportcert -alias sub_key -storepass changeit -keypass changeit \
	-keystore keystore.jks -rfc -file server.pem
