package dm

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"

	"github.com/emersion/go-msgauth/dkim"
)

var dkimPrivateKey *rsa.PrivateKey

func init() {
	privateKeyPEM, err := ioutil.ReadFile("./private_key.pem")
	if err != nil {
		log.Fatalf("Failed to read private key: %v", err)
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		log.Fatalf("Failed to parse PEM block containing the private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	dkimPrivateKey = privateKey.(*rsa.PrivateKey)
}

var DkimOptions = &dkim.SignOptions{
	Domain:   "MyServer.com", // Укажите ваш домен
	Selector: "default",      // Укажите селектор DKIM
	Signer:   dkimPrivateKey,
}
