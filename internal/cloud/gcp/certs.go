package gcp

import (
	"context"
	"fmt"
	"math"
	"os"
	"time"

	"google.golang.org/api/certificatemanager/v1"

	"github.com/stxkxs/matlock/internal/cloud"
)

// certManagerAPI is the narrow Certificate Manager surface used by this package.
type certManagerAPI interface {
	ListCertificates(ctx context.Context, parent string) ([]*certificatemanager.Certificate, error)
}

type certManagerAdapter struct{ svc *certificatemanager.Service }

func (a *certManagerAdapter) ListCertificates(ctx context.Context, parent string) ([]*certificatemanager.Certificate, error) {
	var out []*certificatemanager.Certificate
	err := a.svc.Projects.Locations.Certificates.List(parent).Pages(ctx, func(page *certificatemanager.ListCertificatesResponse) error {
		out = append(out, page.Certificates...)
		return nil
	})
	return out, err
}

// ListCertificates returns GCP Certificate Manager certificates expiring within 180 days.
func (p *Provider) ListCertificates(ctx context.Context) ([]cloud.CertFinding, error) {
	if p.projectID == "" {
		return nil, fmt.Errorf("GCP project ID is required")
	}
	now := time.Now()
	var findings []cloud.CertFinding

	parent := fmt.Sprintf("projects/%s/locations/-", p.projectID)
	certs, err := p.certManager.ListCertificates(ctx, parent)
	if err != nil {
		// Certificate Manager API may not be enabled — warn and return empty
		fmt.Fprintf(os.Stderr, "warn: gcp certificate manager: %v (API may not be enabled)\n", err)
		return nil, nil
	}
	for _, cert := range certs {
		if cert.ExpireTime == "" {
			continue
		}
		expiry, err := time.Parse(time.RFC3339, cert.ExpireTime)
		if err != nil {
			continue
		}
		daysLeft := int(math.Floor(expiry.Sub(now).Hours() / 24))
		if daysLeft > 180 {
			continue
		}
		sev, status := cloud.CertSeverity(daysLeft)
		domain := cert.Name
		if idx := lastSlash(cert.Name); idx >= 0 {
			domain = cert.Name[idx+1:]
		}
		findings = append(findings, cloud.CertFinding{
			Severity:  sev,
			Status:    status,
			Provider:  "gcp",
			Domain:    domain,
			ARN:       cert.Name,
			ExpiresAt: expiry,
			DaysLeft:  daysLeft,
			Detail:    fmt.Sprintf("certificate %s expires in %d days", domain, daysLeft),
		})
	}
	return findings, nil
}

func lastSlash(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}
