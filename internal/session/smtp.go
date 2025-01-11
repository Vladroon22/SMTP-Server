package session

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	golog "github.com/Vladroon22/GoLog"
	"github.com/Vladroon22/SmptServer/internal/dm"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-smtp"
)

// Backend реализует интерфейс smtp.Backend
type Backend struct {
	Logger *golog.Logger
}

// NewSession создает новую сессию SMTP
func (bkd *Backend) NewSession(_ *smtp.Conn) (smtp.Session, error) {
	return &Session{
		logger: bkd.Logger,
		To:     make([]string, 0),
	}, nil
}

// Session представляет SMTP-сессию
type Session struct {
	logger *golog.Logger
	From   string
	To     []string
}

// Mail обрабатывает команду MAIL FROM
func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	s.logger.Infoln("Mail from:", from)
	s.From = from
	return nil
}

// Rcpt обрабатывает команду RCPT TO
func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	s.logger.Infoln("RCPT To:", to)
	s.To = append(s.To, to)
	return nil
}

// Data обрабатывает команду DATA
func (s *Session) Data(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	s.logger.Infoln("Received message: ", string(data))
	for _, recipient := range s.To {
		if err := sendMail(s.From, recipient, data); err != nil {
			s.logger.Infof("Failed to send email to %s: %v\n", recipient, err)
		} else {
			s.logger.Infof("Email sent successfully to %s\n", recipient)
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
	s.logger.Infoln("Session reset")
}

func (s *Session) Logout() error {
	s.logger.Infoln("QUIT")
	return nil
}

func lookupMX(domain string) ([]*net.MX, error) {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return nil, fmt.Errorf("error looking up MX records: %v", err)
	}
	return mxRecords, nil
}

func sendMail(from string, to string, data []byte) error {
	domain := strings.Split(to, "@")[1]

	mxRecords, err := lookupMX(domain)
	if err != nil {
		return err
	}

	for _, mx := range mxRecords {
		host := mx.Host

		for _, port := range []int{25, 587, 465} {
			address := fmt.Sprintf("%s:%d", host, port)

			var c *smtp.Client
			var err error

			switch port {
			case 465:
				tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
				conn, err := tls.Dial("tcp", address, tlsConfig)
				if err != nil {
					continue
				}
				c = smtp.NewClient(conn)

			case 25, 587:
				tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
				c, err = smtp.DialStartTLS(address, tlsConfig)
				if err != nil {
					continue
				}
			}

			if err != nil {
				continue
			}

			var b bytes.Buffer
			if err := dkim.Sign(&b, bytes.NewReader(data), dm.DkimOptions); err != nil {
				c.Close()
				return fmt.Errorf("failed to sign email with DKIM: %v", err)
			}
			signedData := b.Bytes()

			if err := c.Mail(from, &smtp.MailOptions{}); err != nil {
				c.Close()
				continue
			}

			if err := c.Rcpt(to, &smtp.RcptOptions{}); err != nil {
				c.Close()
				continue
			}

			w, err := c.Data()
			if err != nil {
				c.Close()
				continue
			}

			if _, err := w.Write(signedData); err != nil {
				c.Close()
				continue
			}

			if err := w.Close(); err != nil {
				c.Close()
				continue
			}

			c.Quit()
			return nil
		}
	}

	return errors.New("failed to send email to " + to)
}
