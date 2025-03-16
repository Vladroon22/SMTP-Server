package dm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"time"

	"github.com/emersion/go-msgauth/dkim"
)

var (
	dkimPrivateKey *rsa.PrivateKey
	certs          []tls.Certificate
)

func createCerts() {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generate key: %v", err)
	}

	// Создание шаблона сертификата
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		log.Fatalf("Ошибка создания сертификата: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	// Создание tls.Certificate
	cert, err := tls.X509KeyPair(certPEM, privKeyPEM)
	if err != nil {
		log.Fatalf("Ошибка создания tls.Certificate: %v", err)
	}

	certs = append(certs, cert)
}

func init() {
	go createCerts()

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

func GetCerts() []tls.Certificate {
	return certs
}

var DkimOptions = &dkim.SignOptions{
	Domain:   "smtp.custom-server.com", // Укажите ваш домен
	Selector: "default",                // Укажите селектор DKIM
	Signer:   dkimPrivateKey,
}
