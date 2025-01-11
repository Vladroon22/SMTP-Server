
.PHONY:

run:	
	openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
	go build -o smtp cmd/main.go
	./smtp
