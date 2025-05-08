package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Vladroon22/SmptServer/internal/session"
	"github.com/emersion/go-smtp"
)

func main() {
	s := smtp.NewServer(&session.Backend{})

	s.Addr = ":2525"
	s.Domain = "smtp.custom-server.com"
	s.WriteTimeout = 60 * time.Second
	s.ReadTimeout = 60 * time.Second
	s.MaxMessageBytes = 1024 * 1024
	s.MaxRecipients = 50
	s.AllowInsecureAuth = true
	s.EnableSMTPUTF8 = true

	log.Println("Starting SMTP server --> ", s.Addr)
	go func() {
		if err := s.ListenAndServe(); err != nil {
			log.Println(err)
			os.Exit(1)
		}
	}()

	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	<-exit

	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if err := s.Shutdown(ctx); err != nil {
			log.Println(err)
			return
		}
	}()
	log.Println("Server stopped")
}
