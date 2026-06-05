package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/nanohype/cloudgov/internal/cloud"
)

type mockACM struct {
	summaries []acmtypes.CertificateSummary
	listErr   error
	listCalls int
	describes map[string]*acmtypes.CertificateDetail // arn -> detail
	descErr   error
}

func (m *mockACM) ListCertificates(_ context.Context, _ *acm.ListCertificatesInput, _ ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	if m.listCalls > 0 {
		return &acm.ListCertificatesOutput{}, nil
	}
	m.listCalls++
	return &acm.ListCertificatesOutput{CertificateSummaryList: m.summaries}, nil
}

func (m *mockACM) DescribeCertificate(_ context.Context, in *acm.DescribeCertificateInput, _ ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
	if m.descErr != nil {
		return nil, m.descErr
	}
	if d, ok := m.describes[awssdk.ToString(in.CertificateArn)]; ok {
		return &acm.DescribeCertificateOutput{Certificate: d}, nil
	}
	return nil, errors.New("not found")
}

func makeCert(arn, domain string, expiresIn time.Duration) acmtypes.CertificateDetail {
	notAfter := time.Now().Add(expiresIn)
	return acmtypes.CertificateDetail{
		CertificateArn: awssdk.String(arn),
		DomainName:     awssdk.String(domain),
		NotAfter:       &notAfter,
	}
}

func TestListCertificates(t *testing.T) {
	expiringSoon := makeCert("arn:cert/1", "example.com", 7*24*time.Hour)
	expiringLater := makeCert("arn:cert/2", "later.com", 60*24*time.Hour)
	farFuture := makeCert("arn:cert/3", "future.com", 365*24*time.Hour)

	p := &Provider{acm: &mockACM{
		summaries: []acmtypes.CertificateSummary{
			{CertificateArn: awssdk.String("arn:cert/1")},
			{CertificateArn: awssdk.String("arn:cert/2")},
			{CertificateArn: awssdk.String("arn:cert/3")},
		},
		describes: map[string]*acmtypes.CertificateDetail{
			"arn:cert/1": &expiringSoon,
			"arn:cert/2": &expiringLater,
			"arn:cert/3": &farFuture,
		},
	}}

	got, err := p.ListCertificates(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The provider lists every issued cert; windowing by --days is the scanner's
	// job, so the far-future cert is returned here (it would be filtered later).
	if len(got) != 3 {
		t.Errorf("expected 3 findings (all issued certs), got %d: %v", len(got), got)
	}
	byDomain := make(map[string]cloud.CertFinding)
	for _, f := range got {
		byDomain[f.Domain] = f
		if f.Provider != "aws" {
			t.Errorf("provider: got %q", f.Provider)
		}
	}
	if f, ok := byDomain["future.com"]; !ok {
		t.Error("365-day cert should be returned by the provider (scanner applies --days)")
	} else if f.DaysLeft < 360 || f.Severity != cloud.SeverityLow {
		t.Errorf("future.com: DaysLeft=%d Severity=%q, want ~365 and LOW", f.DaysLeft, f.Severity)
	}
}

func TestListCertificates_DescribeFailureSkipsCert(t *testing.T) {
	expiringSoon := makeCert("arn:cert/1", "example.com", 7*24*time.Hour)
	p := &Provider{acm: &mockACM{
		summaries: []acmtypes.CertificateSummary{
			{CertificateArn: awssdk.String("arn:cert/missing")},
			{CertificateArn: awssdk.String("arn:cert/1")},
		},
		describes: map[string]*acmtypes.CertificateDetail{
			"arn:cert/1": &expiringSoon,
		},
	}}
	got, err := p.ListCertificates(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 finding (other cert undescribable), got %d", len(got))
	}
}

func TestListCertificates_ListErrorIsFatal(t *testing.T) {
	p := &Provider{acm: &mockACM{listErr: errors.New("auth fail")}}
	_, err := p.ListCertificates(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestListCertificates_NilNotAfterSkipped(t *testing.T) {
	noExpiry := acmtypes.CertificateDetail{
		CertificateArn: awssdk.String("arn:cert/1"),
		DomainName:     awssdk.String("example.com"),
		// NotAfter is nil
	}
	p := &Provider{acm: &mockACM{
		summaries: []acmtypes.CertificateSummary{
			{CertificateArn: awssdk.String("arn:cert/1")},
		},
		describes: map[string]*acmtypes.CertificateDetail{
			"arn:cert/1": &noExpiry,
		},
	}}
	got, err := p.ListCertificates(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 findings (cert has no NotAfter), got %d", len(got))
	}
}
