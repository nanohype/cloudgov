package cloud

import (
	"context"
	"time"
)

// CertStatus describes how close a certificate is to expiry.
type CertStatus string

const (
	CertExpired  CertStatus = "EXPIRED"
	CertCritical CertStatus = "EXPIRING_7D"
	CertHigh     CertStatus = "EXPIRING_30D"
	CertMedium   CertStatus = "EXPIRING_60D"
	CertLow      CertStatus = "EXPIRING_90D"
)

// CertFinding is a single certificate expiry observation.
type CertFinding struct {
	Severity  Severity
	Status    CertStatus
	Provider  string
	Domain    string
	ARN       string
	Region    string
	ExpiresAt time.Time
	DaysLeft  int
	Detail    string
}

// CertProvider lists TLS certificates and their expiry status.
type CertProvider interface {
	Provider
	ListCertificates(ctx context.Context) ([]CertFinding, error)
}

// CertSeverity returns the severity for a certificate based on days until expiry.
func CertSeverity(daysLeft int) (Severity, CertStatus) {
	switch {
	case daysLeft < 0:
		return SeverityCritical, CertExpired
	case daysLeft < 7:
		return SeverityCritical, CertCritical
	case daysLeft < 30:
		return SeverityHigh, CertHigh
	case daysLeft < 60:
		return SeverityMedium, CertMedium
	default:
		return SeverityLow, CertLow
	}
}
