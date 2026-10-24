package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hicancan/sdp-tunnel/internal/captcha"
	"github.com/hicancan/sdp-tunnel/internal/config"
	"github.com/hicancan/sdp-tunnel/internal/gateway"
)

type fatalError struct{ error }

func (e fatalError) Unwrap() error { return e.error }

func loadSession(path string) (*gateway.Session, error) {
	session, err := gateway.LoadSession(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return session, err
}

type sessionValidator interface {
	ValidateSession(context.Context, *gateway.Session) (*gateway.Session, error)
}

func validateSession(ctx context.Context, client sessionValidator, session *gateway.Session) (*gateway.Session, error) {
	if session == nil {
		return nil, nil
	}
	validated, err := client.ValidateSession(ctx, session)
	if errors.Is(err, gateway.ErrSessionInvalid) {
		return nil, nil
	}
	return validated, err
}

// renew exchanges a rejected session for a fresh one without a captcha, then
// validates it so the controller policy (and with it the campus resolver) is
// loaded exactly as a login would.
func renew(ctx context.Context, client *gateway.Client, stale *gateway.Session) (*gateway.Session, error) {
	renewed, err := client.RenewSession(ctx, stale)
	if err != nil {
		return nil, err
	}
	validated, err := client.ValidateSession(ctx, renewed)
	if err != nil {
		return nil, err
	}
	return validated, nil
}

// logIn spends a captcha. It is the last rung of the ladder in acquire.
func logIn(ctx context.Context, client *gateway.Client, credentials config.AuthConfig, reader *captcha.Recognizer) (*gateway.Session, error) {
	if credentials.Username == "" || credentials.Password == "" {
		return nil, fatalError{errors.New("no valid cached session and no login credentials")}
	}
	if reader == nil {
		return nil, fatalError{errors.New("logging in needs a captcha model; set captcha.model")}
	}
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			if err := wait(ctx, 250*time.Millisecond); err != nil {
				return nil, err
			}
		}
		key, err := client.GenerateKey(ctx)
		if err != nil {
			return nil, err
		}
		image, err := client.GetCaptcha(ctx)
		if err != nil {
			return nil, err
		}
		code, err := reader.Recognize(image)
		if err != nil || strings.Contains(code, "?") {
			continue
		}
		session, err := client.Login(ctx, credentials.Username, credentials.Password, key, code)
		if errors.Is(err, gateway.ErrCaptchaRejected) {
			continue
		}
		if errors.Is(err, gateway.ErrLoginRejected) {
			return nil, fatalError{err}
		}
		if err != nil {
			return nil, err
		}
		// A fresh login still needs its policy loaded before the tunnel opens.
		validated, err := client.ValidateSession(ctx, session)
		if errors.Is(err, gateway.ErrSessionInvalid) {
			return nil, fatalError{err}
		}
		return validated, err
	}
	return nil, fatalError{fmt.Errorf("captcha recognition was rejected after 3 attempts: %w", gateway.ErrCaptchaRejected)}
}

func wait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
