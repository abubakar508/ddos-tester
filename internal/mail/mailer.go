package mail

type Mailer struct{}

// NewMailer returns a no-op Mailer
func NewMailer() *Mailer {
	return &Mailer{}
}

// No-op methods to satisfy interface if needed
func (m *Mailer) SendEmail(to, subject, body string, isHTML bool) error {
	return nil
}

func (m *Mailer) SendEmailWithAttachments(to, subject, body string, attachmentPaths []string, isHTML bool) error {
	return nil
}
