#!/bin/bash

cd /home/lanforge/hs20/ca
killall openssl
./ocsp-responder.sh&

while true
do
	./ocsp-update-cache.sh
	sleep 60
done
