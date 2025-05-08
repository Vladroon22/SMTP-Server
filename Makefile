.PHONY:

build:
	sudo docker build -t smpt .

run:
	openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
	sudo docker run --name=MySmtpServer -p 2525:2525 -d smpt:latest

certs:
	openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

exe:	
	go build -o smtp cmd/main.go
	./smtp
