package models

import "time"

// Notification represents a notification to be sent
type Notification struct {
	ID            int64     `json:"id"`
	Type          string    `json:"type"` // email, slack, webhook
	Channel       string    `json:"channel"` // email address, slack channel, webhook URL
	Event         string    `json:"event"` // cert_expiring, cert_expired, cert_revoked, ca_rotated
	Subject       string    `json:"subject"`
	Body          string    `json:"body"`
	Status        string    `json:"status"` // pending, sent, failed
	Retries       int       `json:"retries"`
	ErrorMessage  *string   `json:"error_message,omitempty"`
	ScheduledFor  time.Time `json:"scheduled_for"`
	SentAt        *time.Time `json:"sent_at,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// NotificationType represents notification delivery types
const (
	NotificationTypeEmail   = "email"
	NotificationTypeSlack   = "slack"
	NotificationTypeWebhook = "webhook"
)

// NotificationEvent represents event types that trigger notifications
const (
	NotificationEventCertExpiring = "cert_expiring"
	NotificationEventCertExpired  = "cert_expired"
	NotificationEventCertRevoked  = "cert_revoked"
	NotificationEventCertIssued   = "cert_issued"
	NotificationEventCARotated    = "ca_rotated"
	NotificationEventCAExpiring   = "ca_expiring"
	NotificationEventPolicyViolation = "policy_violation"
)

// NotificationStatus represents notification delivery status
const (
	NotificationStatusPending = "pending"
	NotificationStatusSent    = "sent"
	NotificationStatusFailed  = "failed"
)

