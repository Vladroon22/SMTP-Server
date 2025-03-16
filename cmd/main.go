package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	golog "github.com/Vladroon22/GoLog"
	"github.com/Vladroon22/SmptServer/internal/session"
	"github.com/emersion/go-smtp"
)

func main() {
	logger := golog.New()
	s := smtp.NewServer(&session.Backend{})

	s.Addr = ":2525"
	s.Domain = "smtp.custom-server.com"
	s.WriteTimeout = 60 * time.Second
	s.ReadTimeout = 60 * time.Second
	s.MaxMessageBytes = 1024 * 1024
	s.MaxRecipients = 50
	s.AllowInsecureAuth = true
	s.EnableSMTPUTF8 = true

	logger.Infoln("Starting SMTP server --> ", s.Addr)
	go func() {
		if err := s.ListenAndServe(); err != nil {
			logger.Fatalln(err)
		}
	}()

	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	<-exit

	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if err := s.Shutdown(ctx); err != nil {
			logger.Errorln(err)
			return
		}
	}()
	logger.Infoln("Server stopped")
}
