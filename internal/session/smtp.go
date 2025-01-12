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

type Session struct {
	logger *golog.Logger
	From   string
	To     []string
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	s.logger.Infoln("Mail from:", from)
	s.From = from
	return nil
}

func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	s.logger.Infoln("RCPT To:", to)
	s.To = append(s.To, to)
	return nil
}

func (s *Session) Data(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		s.logger.Errorln(err)
		return err
	}

	s.logger.Infoln("Received message: ", string(data))
	for _, recipient := range s.To {
		if err := s.sendMail(s.From, recipient, data); err != nil {
			s.logger.Infof("Failed to send email to %s: %v\n", recipient, err)
		} else {
			s.logger.Infoln("Email sent successfully to ", recipient)
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

func (s *Session) lookupMX(domain string) ([]*net.MX, error) {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		s.logger.Errorln("error looking up MX records: " + err.Error())
		return nil, errors.New(err.Error())
	}
	return mxRecords, nil
}

func (s *Session) sendMail(from string, to string, data []byte) error {
	domain := strings.Split(to, "@")[1]

	mxRecords, err := s.lookupMX(domain)
	if err != nil {
		s.logger.Errorln(err)
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
					s.logger.Errorln(err)
					continue
				}
				c = smtp.NewClient(conn)

			case 25, 587:
				c, err = smtp.Dial(address)
				if err != nil {
					s.logger.Errorln(err)
					continue
				}

				if port == 587 {
					if c, err = smtp.DialStartTLS(address, &tls.Config{ServerName: host}); err != nil {
						c.Close()
						s.logger.Errorln(err)
						continue
					}
				}
			}

			if err != nil {
				continue
			}

			var b bytes.Buffer
			if err := dkim.Sign(&b, bytes.NewReader(data), dm.DkimOptions); err != nil {
				c.Close()
				s.logger.Errorln("failed to sign email with DKIM: ", err)
				return errors.New(err.Error())
			}
			signedData := b.Bytes()

			if err := c.Mail(from, &smtp.MailOptions{}); err != nil {
				c.Close()
				s.logger.Errorln(err)
				continue
			}

			if err := c.Rcpt(to, &smtp.RcptOptions{}); err != nil {
				c.Close()
				s.logger.Errorln(err)
				continue
			}

			w, err := c.Data()
			if err != nil {
				c.Close()
				s.logger.Errorln(err)
				continue
			}

			if _, err := w.Write(signedData); err != nil {
				c.Close()
				s.logger.Errorln(err)
				continue
			}

			if err := w.Close(); err != nil {
				c.Close()
				s.logger.Errorln(err)
				continue
			}

			c.Quit()
			return nil
		}
	}

	return errors.New("failed to send email to " + to)
}
