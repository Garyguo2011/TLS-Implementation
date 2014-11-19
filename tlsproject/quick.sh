#!/bin/bash

count=1
while [[ count -lt 100 ]]; do
	./client_test -i 54.148.53.246 -c client_cert.crt -d client_private.key -m client_modulus.key
	let count+=1
done
