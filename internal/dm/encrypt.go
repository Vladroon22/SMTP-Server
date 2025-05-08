package dm

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/emersion/go-msgauth/dkim"
)

var (
	dkimPrivateKey *rsa.PrivateKey
	certs          []tls.Certificate
	certsOnce      sync.Once
)

func createCerts() {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generate key: %v", err)
	}

	// Заполняем Subject
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"SMTP CUSTOM SERVER"},
			CommonName:   "smtp.custom-server.com", // Ваш домен
		},
		DNSNames:              []string{"smtp.custom-server.com"}, // Важно для валидации
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		log.Fatalf("error: create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	cert, err := tls.X509KeyPair(certPEM, privKeyPEM)
	if err != nil {
		log.Fatalf("error create tls.Certificate: %v", err)
	}

	certs = append(certs, cert)
}

func init() {
	certsOnce.Do(createCerts)

	privateKeyPEM, err := os.ReadFile("./private_key.pem")
	if err != nil {
		fmt.Printf("Failed to read private key: %v", err)
		os.Exit(1)
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		fmt.Printf("Failed to parse PEM block containing the private key")
		os.Exit(1)
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("Failed to parse private key: %v", err)
		os.Exit(1)
	}

	var ok bool
	dkimPrivateKey, ok = privateKey.(*rsa.PrivateKey)
	if !ok {
		fmt.Printf("Expected RSA private key, got %T", privateKey)
		os.Exit(1)
	}
}

var DkimOptions = &dkim.SignOptions{
	Domain:   "custom-server.com",
	Selector: "default",
	Signer:   dkimPrivateKey,
	Hash:     crypto.SHA256,
}

func GetCerts() []tls.Certificate {
	return certs
}
