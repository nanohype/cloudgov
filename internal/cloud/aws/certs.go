package aws

import (
	"context"
	"fmt"
	"math"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/nanohype/cloudgov/internal/cloud"
)

// acmAPI is the narrow ACM surface used by this package.
type acmAPI interface {
	ListCertificates(ctx context.Context, params *acm.ListCertificatesInput, optFns ...func(*acm.Options)) (*acm.ListCertificatesOutput, error)
	DescribeCertificate(ctx context.Context, params *acm.DescribeCertificateInput, optFns ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error)
}

// ListCertificates returns every issued ACM certificate with its expiry status.
// The expiry window is not applied here: the certs scanner is the single authority
// on the --days threshold (cmd and audit both pass it), so capping here would
// silently hide certificates a caller asked to see with --days beyond the cap.
func (p *Provider) ListCertificates(ctx context.Context) ([]cloud.CertFinding, error) {
	pager := acm.NewListCertificatesPaginator(p.acm, &acm.ListCertificatesInput{
		CertificateStatuses: []acmtypes.CertificateStatus{acmtypes.CertificateStatusIssued},
	})

	now := time.Now()
	var findings []cloud.CertFinding

	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list certificates: %w", err)
		}
		for _, summary := range page.CertificateSummaryList {
			arn := awssdk.ToString(summary.CertificateArn)
			detail, err := p.acm.DescribeCertificate(ctx, &acm.DescribeCertificateInput{
				CertificateArn: awssdk.String(arn),
			})
			if err != nil {
				// Skip certs we can't describe
				continue
			}
			cert := detail.Certificate
			if cert == nil || cert.NotAfter == nil {
				continue
			}

			daysLeft := int(math.Floor(cert.NotAfter.Sub(now).Hours() / 24))
			sev, status := cloud.CertSeverity(daysLeft)
			domain := awssdk.ToString(cert.DomainName)
			findings = append(findings, cloud.CertFinding{
				Severity:  sev,
				Status:    status,
				Provider:  "aws",
				Domain:    domain,
				ARN:       arn,
				Region:    p.cfg.Region,
				ExpiresAt: *cert.NotAfter,
				DaysLeft:  daysLeft,
				Detail:    fmt.Sprintf("certificate for %s expires in %d days", domain, daysLeft),
			})
		}
	}
	return findings, nil
}
