package smtp

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

type Security string

const (
	SecuritySTARTTLS Security = "starttls"
	SecuritySSL      Security = "ssl"
	SecurityNone     Security = "none"
)

type Request struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Security Security `json:"security"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	From     string   `json:"from"`
	To       string   `json:"to"`
	Subject  string   `json:"subject"`
	Text     string   `json:"text"`
	HTML     bool     `json:"html"`
}

type Step struct {
	Step   string    `json:"step"`
	OK     bool      `json:"ok"`
	Detail string    `json:"detail"`
	At     time.Time `json:"at"`
}

type Result struct {
	OK    bool   `json:"ok"`
	Steps []Step `json:"steps"`
	Error string `json:"error,omitempty"`
}

func step(name string, ok bool, detail string) Step {
	return Step{Step: name, OK: ok, Detail: detail, At: time.Now().UTC()}
}

func RunTest(req Request) Result {
	steps := make([]Step, 0, 4)

	host := strings.TrimSpace(req.Host)
	from := strings.TrimSpace(req.From)
	to := strings.TrimSpace(req.To)
	user := strings.TrimSpace(req.Username)
	sec := req.Security
	if sec == "" {
		sec = SecuritySTARTTLS
	}

	if host == "" {
		return Result{OK: false, Steps: steps, Error: "SMTP host is required"}
	}
	if req.Port < 1 || req.Port > 65535 {
		return Result{OK: false, Steps: steps, Error: "Valid SMTP port is required"}
	}
	if from == "" || to == "" {
		return Result{OK: false, Steps: steps, Error: "From and To are required"}
	}
	if user == "" || req.Password == "" {
		return Result{OK: false, Steps: steps, Error: "Username and password are required"}
	}
	if !looksLikeEmail(from) || !looksLikeEmail(to) {
		return Result{OK: false, Steps: steps, Error: "From and To must look like email addresses"}
	}

	steps = append(steps, step("validate", true, fmt.Sprintf("%s:%d (%s)", host, req.Port, sec)))

	subject := strings.TrimSpace(req.Subject)
	if subject == "" {
		subject = "SMTP test from tools.riyanathariq.space"
	}
	body := strings.TrimSpace(req.Text)
	if body == "" {
		body = fmt.Sprintf(
			"SMTP test OK at %s\nSent via tools.riyanathariq.space SMTP Tester (BYO credentials).",
			time.Now().UTC().Format(time.RFC3339),
		)
	}
	if len(subject) > 200 {
		return Result{OK: false, Steps: steps, Error: "Subject too long (max 200)"}
	}
	if len(body) > 20_000 {
		return Result{OK: false, Steps: steps, Error: "Body too long (max 20000)"}
	}

	contentType := "text/plain; charset=UTF-8"
	if req.HTML {
		contentType = "text/html; charset=UTF-8"
	}

	msg := strings.Join([]string{
		"From: " + from,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: " + contentType,
		"X-Mailer: tools-api.riyanathariq.space",
		"",
		body,
	}, "\r\n")

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", req.Port))
	auth := smtp.PlainAuth("", user, req.Password, host)

	var err error
	switch sec {
	case SecuritySSL:
		err = sendImplicitTLS(addr, host, auth, from, to, []byte(msg))
	case SecurityNone:
		err = sendPlain(addr, host, auth, from, to, []byte(msg))
	default:
		err = sendSTARTTLS(addr, host, auth, from, to, []byte(msg))
	}
	if err != nil {
		steps = append(steps, step("send", false, err.Error()))
		return Result{OK: false, Steps: steps, Error: err.Error()}
	}

	steps = append(steps, step("connect+auth+send", true, "Message accepted by SMTP server"))
	return Result{OK: true, Steps: steps}
}

func looksLikeEmail(s string) bool {
	at := strings.LastIndex(s, "@")
	if at <= 0 || at == len(s)-1 {
		return false
	}
	return strings.Contains(s[at+1:], ".")
}

func sendImplicitTLS(addr, host string, auth smtp.Auth, from, to string, msg []byte) error {
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}
	return smtpOverConn(conn, host, auth, from, to, msg)
}

func sendSTARTTLS(addr, host string, auth smtp.Auth, from, to string, msg []byte) error {
	conn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	} else {
		return fmt.Errorf("server does not support STARTTLS")
	}
	if auth != nil {
		if ok, _ := client.Extension("AUTH"); !ok {
			return fmt.Errorf("server does not support AUTH")
		}
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	return dataSend(client, from, to, msg)
}

func sendPlain(addr, host string, auth smtp.Auth, from, to string, msg []byte) error {
	conn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	return smtpOverConn(conn, host, auth, from, to, msg)
}

func smtpOverConn(conn net.Conn, host string, auth smtp.Auth, from, to string, msg []byte) error {
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	return dataSend(client, from, to, msg)
}

func dataSend(client *smtp.Client, from, to string, msg []byte) error {
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("end DATA: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("QUIT: %w", err)
	}
	return nil
}
