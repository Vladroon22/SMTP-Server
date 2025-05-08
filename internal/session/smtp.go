package session

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/Vladroon22/SmptServer/internal/dm"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-smtp"
)

// Backend implements interface smtp.Backend
type Backend struct{}

// NewSession creates new session SMTP
func (bkd *Backend) NewSession(_ *smtp.Conn) (smtp.Session, error) {
	return &Session{To: make([]string, 0)}, nil
}

type Session struct {
	From string
	To   []string
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	log.Println("Mail from:", from)
	s.From = from
	return nil
}

func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	log.Println("RCPT To:", to)
	s.To = append(s.To, to)
	return nil
}

func (s *Session) Data(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		log.Println(err)
		return err
	}

	log.Println("Received message: ", string(data))
	for _, recipient := range s.To {
		if err := s.sendMail(s.From, recipient, data); err != nil {
			log.Printf("Failed to send email to %s: %v\n", recipient, err)
		}
	}
	return nil
}

func (s *Session) AuthPlain(username, password string) error {
	return nil
}

func (s *Session) Reset() {
	s.From = ""
	s.To = make([]string, 0)
	log.Println("Session reset")
}

func (s *Session) Logout() error {
	log.Println("QUIT")
	return nil
}

func (s *Session) lookupMX(domain string) ([]*net.MX, error) {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		log.Println("error looking up MX records: " + err.Error())
		return nil, errors.New(err.Error())
	}
	return mxRecords, nil
}

func (s *Session) sendMail(from string, to string, data []byte) error {
	domain := strings.Split(to, "@")[1]

	mxRecords, err := s.lookupMX(domain)
	if err != nil {
		log.Println(err)
		return err
	}

	for _, mx := range mxRecords {
		host := mx.Host

		var smtpClient *smtp.Client
		defer smtpClient.Quit()

		for _, port := range []int{25, 587, 465} {
			var address string
			ip := net.ParseIP(host)
			if ip.To16() == nil {
				address = fmt.Sprintf("%s:%d", host, port)
			} else {
				address = fmt.Sprintf("[%s]:%d", host, port)
			}

			switch port {
			case 465:
				tlsConfig := &tls.Config{
					ServerName:         host,
					MinVersion:         tls.VersionTLS12,
					InsecureSkipVerify: false,
					Certificates:       dm.GetCerts(),
				}

				conn, err := tls.Dial("tcp", address, tlsConfig)
				if err != nil {
					log.Println(err)
					return err
				}

				smtpClient = smtp.NewClient(conn)
			case 587:
				conn, err := net.DialTimeout("tcp", address, 10*time.Second)
				if err != nil {
					log.Println(err)
					return err
				}

				tlsConfig := &tls.Config{
					ServerName:         host,
					MinVersion:         tls.VersionTLS12,
					InsecureSkipVerify: false,
					Certificates:       dm.GetCerts(),
				}

				var errTLS error
				if smtpClient, errTLS = smtp.DialTLS(address, tlsConfig); errTLS != nil {
					smtpClient.Close()
					log.Println(err)
					return err
				}

				smtpClient = smtp.NewClient(conn)
			case 25:
				conn, err := net.DialTimeout("tcp", address, 10*time.Second)
				if err != nil {
					log.Println(err)
					continue
				}

				smtpClient = smtp.NewClient(conn)
			}
		}

		var b bytes.Buffer
		if err := dkim.Sign(&b, bytes.NewReader(data), dm.DkimOptions); err != nil {
			smtpClient.Close()
			log.Println("failed to sign email with DKIM: ", err)
			return errors.New(err.Error())
		}
		signedData := b.Bytes()

		if err := smtpClient.Mail(from, &smtp.MailOptions{}); err != nil {
			smtpClient.Close()
			log.Println(err)
			continue
		}

		if err := smtpClient.Rcpt(to, &smtp.RcptOptions{}); err != nil {
			smtpClient.Close()
			log.Println(err)
			continue
		}

		w, err := smtpClient.Data()
		if err != nil {
			smtpClient.Close()
			log.Println(err)
			continue
		}

		if _, err := w.Write(signedData); err != nil {
			smtpClient.Close()
			log.Println(err)
			continue
		}

		if err := w.Close(); err != nil {
			smtpClient.Close()
			log.Println(err)
			continue
		}
	}
	return errors.New("failed to lookup mx records")
}
