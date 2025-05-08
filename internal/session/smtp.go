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
		} else {
			log.Println("Email sent successfully to ", recipient)
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
		var c *smtp.Client
		var err error

		for _, port := range []int{25, 587, 465} {
			address := fmt.Sprintf("%s:%d", host, port)

			switch port {
			case 465:
				tlsConfig := &tls.Config{
					MinVersion:         tls.VersionTLS12,
					InsecureSkipVerify: true,
					Certificates:       dm.GetCerts(),
				}
				conn, err := tls.Dial("tcp", host, tlsConfig)
				if err != nil {
					log.Println(err)
					return err
				}
				c = smtp.NewClient(conn)
			case 25:
				var err error
				c, err = smtp.Dial(address)
				if err != nil {
					log.Println(err)
					return err
				}
			case 587:
				var err error
				if c, err = smtp.DialStartTLS(address,
					&tls.Config{
						ServerName:         host,
						MinVersion:         tls.VersionTLS12,
						InsecureSkipVerify: true,
						Certificates:       dm.GetCerts(),
					}); err != nil {
					c.Close()
					log.Println(err)
					return err
				}
			}
		}

		var b bytes.Buffer
		if err := dkim.Sign(&b, bytes.NewReader(data), dm.DkimOptions); err != nil {
			c.Close()
			log.Println("failed to sign email with DKIM: ", err)
			return errors.New(err.Error())
		}
		signedData := b.Bytes()

		if err := c.Mail(from, &smtp.MailOptions{}); err != nil {
			c.Close()
			log.Println(err)
			continue
		}

		if err := c.Rcpt(to, &smtp.RcptOptions{}); err != nil {
			c.Close()
			log.Println(err)
			continue
		}

		w, err := c.Data()
		if err != nil {
			c.Close()
			log.Println(err)
			continue
		}

		if _, err := w.Write(signedData); err != nil {
			c.Close()
			log.Println(err)
			continue
		}

		if err := w.Close(); err != nil {
			c.Close()
			log.Println(err)
			continue
		}

		c.Quit()
	}
	return nil
}
