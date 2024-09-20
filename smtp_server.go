package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/maelvls/foncia/logutil"
)

// ServeSMTP is blocking and can be unblocked by cancelling the context. This
// SMTP server used to receive email-only mission orders ("ordres de service").
func ServeSMTP(ctx context.Context, db *sql.DB, smtpListen net.Listener) error {
	s := smtp.NewServer(smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
		logutil.Infof("ServeSMTP: new connection from %s", c.Hostname())
		sess := &Session{}
		return sess, nil
	}))

	s.ErrorLog = log.Default()
	go func() {
		// Unlike http.Server, smtp.Server doesn't have a built-in context. This
		// func works around that.
		<-ctx.Done()
		logutil.Infof("ServeSMTP: context cancelled, stopping the SMTP server")
		err := s.Close()
		if err != nil {
			logutil.Errorf("ServeSMTP: while closing SMTP server: %v", err)
		}
	}()

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(fmt.Errorf("ServeSMTP: cancelled without a reason"))

	// This "single use" waitgroup allows us to wait for the SMTP server to
	// cleanly stop before ServeSMTP returns. We could have used a channel
	// instead.
	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel(fmt.Errorf("ServeSMTP: SMTP server stopped for some reason"))
		logutil.Infof("serving SMTP server on %s", smtpListen.Addr())

		err := s.Serve(smtpListen)
		if err != nil {
			cancel(fmt.Errorf("while serving SMTP server: %w", err))
			return
		}
	}()

	wg.Wait()
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}

	return nil
}

// Session is used by servers to respond to an SMTP client.
//
// The methods are called when the remote client issues the matching command.
type Session struct {
	osNumber      string
	date          time.Time
	subject       string
	plaintextPart string
}

// Discard currently processed message.
func (s *Session) Reset() {
	logutil.Debugf("email: reset")
	*s = Session{}
}

// Free all resources associated with session.
func (s *Session) Logout() error {
	logutil.Debugf("email: logout")
	return nil
}

// Set return path for currently processed message.
func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	logutil.Debugf("email: received email from %q", from)
	return nil
}

// Add recipient for currently processed message.
func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	logutil.Debugf("email: received email for %q", to)
	return nil
}

// Set currently processed message contents and send it.
//
// r must be consumed before Data returns.
func (s *Session) Data(r io.Reader) error {
	logutil.Debugf("email: reading DATA block")
	// bytes, err := io.ReadAll(r)
	// if err != nil {
	// 	logutil.Errorf("email: could not read DATA block: %v", err)
	// 	return err
	// }
	// logutil.Debugf("email: DATA block: %s", bytes)

	// Decode the MIME message.
	msg, err := mail.ReadMessage(r)
	if err != nil {
		logutil.Errorf("email: mail.ReadMessage: could not read message: %v", err)
		return err
	}

	// Parse the email date.
	date, err := msg.Header.Date()
	if err != nil {
		logutil.Errorf("email: msg.Header.Date: could not parse email date: %v", err)
		return err
	}

	sub := msg.Header.Get("Subject")

	// Parse the mission number ("Ordre de service in French") from the subject.
	// For example, given the subject:
	//  "Ordre de service N° OSMIL805898844 – 2NRT POMPE ENVIRONNEMENT - 3 RUE BERTRAN 31200 TOULOUSE"
	// we want to extract "OSMIL805898844".

	// Get the content boundary.
	ct := msg.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		logutil.Errorf("email: mime.ParseMediaType: could not parse Content-Type: %v", err)
		return fmt.Errorf("email: mime.ParseMediaType: could not parse Content-Type: %w", err)
	}

	if !strings.HasPrefix(mediaType, "multipart/") {
		logutil.Errorf("email: expected multipart/* but got %s", mediaType)
		return fmt.Errorf("email: expected multipart/* but got %s", mediaType)
	}

	// Parse the body.

	var plaintext string
	multi := multipart.NewReader(msg.Body, params["boundary"])
	buf := strings.Builder{}
	for {
		part, err := multi.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			logutil.Errorf("email: multi.NextPart: could not read part: %v", err)
			return fmt.Errorf("email: multi.NextPart: could not read part: %w", err)
		}

		// We only want to read the text parts.
		ct := part.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "text/") {
			logutil.Debugf("email: skipping part with Content-Type %q", ct)
			continue
		}

		_, err = io.Copy(&buf, part)
		if err != nil {
			logutil.Errorf("email: io.Copy: could not read part: %v", err)
			return fmt.Errorf("email: io.Copy: could not read part: %w", err)
		}

		plaintext = buf.String()
	}

	// For some reason, the service order's email contents, even though it says
	// "plain/text", contains HTML line breaks (<br />). Let's replace them with
	// newlines instead.
	plaintext = strings.ReplaceAll(plaintext, "<br />", "\n")
	plaintext = strings.ReplaceAll(plaintext, "<br/ >", "\n")
	plaintext = strings.ReplaceAll(plaintext, "<br/>", "\n")
	plaintext = strings.ReplaceAll(plaintext, "<br>", "\n")

	s.date = date
	s.subject = sub
	s.plaintextPart = string(plaintext)

	logutil.Infof("email: received email %s with subject %q", osNumber, sub)
	logutil.Infof("email: plain/text part: %s", plaintext)

	return nil
}
