package emailer

// Attachment is a file attached to an outgoing email.
type Attachment struct {
	Name string
	Data []byte
}

// Emailer is implemented by every email backend (SMTP, Sendgrid, ...).
type Emailer interface {
	Send(toName string, to string, subject string, content string, attachments []Attachment) error
}
