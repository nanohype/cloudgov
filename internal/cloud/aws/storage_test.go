package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithy "github.com/aws/smithy-go"
	"github.com/stxkxs/matlock/internal/cloud"
)

// apiErr returns a fake smithy.APIError with the given code.
type apiErr struct{ code string }

func (e *apiErr) Error() string                 { return e.code }
func (e *apiErr) ErrorCode() string             { return e.code }
func (e *apiErr) ErrorMessage() string          { return e.code }
func (e *apiErr) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

type mockS3 struct {
	buckets        []s3types.Bucket
	location       s3types.BucketLocationConstraint
	pubAccessBlock *s3types.PublicAccessBlockConfiguration
	pubAccessErr   error
	encErr         error
	versioning     s3types.BucketVersioningStatus
	versioningErr  error
	loggingEnabled bool
	loggingErr     error
	listBucketsErr error
	getLocationErr error
}

func (m *mockS3) ListBuckets(_ context.Context, _ *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if m.listBucketsErr != nil {
		return nil, m.listBucketsErr
	}
	return &s3.ListBucketsOutput{Buckets: m.buckets}, nil
}

func (m *mockS3) GetBucketLocation(_ context.Context, _ *s3.GetBucketLocationInput, _ ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	if m.getLocationErr != nil {
		return nil, m.getLocationErr
	}
	return &s3.GetBucketLocationOutput{LocationConstraint: m.location}, nil
}

func (m *mockS3) GetPublicAccessBlock(_ context.Context, _ *s3.GetPublicAccessBlockInput, _ ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	if m.pubAccessErr != nil {
		return nil, m.pubAccessErr
	}
	return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: m.pubAccessBlock}, nil
}

func (m *mockS3) GetBucketEncryption(_ context.Context, _ *s3.GetBucketEncryptionInput, _ ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	if m.encErr != nil {
		return nil, m.encErr
	}
	return &s3.GetBucketEncryptionOutput{}, nil
}

func (m *mockS3) GetBucketVersioning(_ context.Context, _ *s3.GetBucketVersioningInput, _ ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	if m.versioningErr != nil {
		return nil, m.versioningErr
	}
	return &s3.GetBucketVersioningOutput{Status: m.versioning}, nil
}

func (m *mockS3) GetBucketLogging(_ context.Context, _ *s3.GetBucketLoggingInput, _ ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
	if m.loggingErr != nil {
		return nil, m.loggingErr
	}
	out := &s3.GetBucketLoggingOutput{}
	if m.loggingEnabled {
		out.LoggingEnabled = &s3types.LoggingEnabled{}
	}
	return out, nil
}

// no-op to satisfy s3API. Tags tests use a dedicated mock that overrides this.
func (m *mockS3) GetBucketTagging(_ context.Context, _ *s3.GetBucketTaggingInput, _ ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error) {
	return &s3.GetBucketTaggingOutput{}, nil
}

// no-op to satisfy s3API. Drift tests use a dedicated mock that overrides this.
func (m *mockS3) HeadBucket(_ context.Context, _ *s3.HeadBucketInput, _ ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	return &s3.HeadBucketOutput{}, nil
}

func newStorageProvider(s *mockS3) *Provider {
	return &Provider{
		s3:          s,
		s3ForRegion: func(_ string) s3API { return s },
	}
}

func TestAuditStorage_NoBuckets(t *testing.T) {
	p := newStorageProvider(&mockS3{})
	got, err := p.AuditStorage(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no findings, got %v", got)
	}
}

func TestAuditStorage_ListBucketsError(t *testing.T) {
	p := newStorageProvider(&mockS3{listBucketsErr: errors.New("auth fail")})
	_, err := p.AuditStorage(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAuditStorage_PublicBucket(t *testing.T) {
	p := newStorageProvider(&mockS3{
		buckets:        []s3types.Bucket{{Name: awssdk.String("public-bucket")}},
		pubAccessErr:   &apiErr{code: "NoSuchPublicAccessBlockConfiguration"},
		loggingEnabled: true,
		versioning:     s3types.BucketVersioningStatusEnabled,
	})
	got, err := p.AuditStorage(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should find: public access (critical) + unencrypted (high). encErr is nil
	// so encryption check doesn't fire — wait, no, GetBucketEncryption defaults
	// to returning empty output which means no finding. So just the public
	// access finding is expected.
	if len(got) != 1 || got[0].Severity != cloud.SeverityCritical || got[0].Type != cloud.BucketPublicAccess {
		t.Errorf("expected one critical public-access finding, got %v", got)
	}
}

func TestAuditStorage_PartiallyBlockedPublicAccess(t *testing.T) {
	// Public access block exists but not all four flags set
	p := newStorageProvider(&mockS3{
		buckets: []s3types.Bucket{{Name: awssdk.String("partial")}},
		pubAccessBlock: &s3types.PublicAccessBlockConfiguration{
			BlockPublicAcls:       awssdk.Bool(true),
			IgnorePublicAcls:      awssdk.Bool(true),
			BlockPublicPolicy:     awssdk.Bool(false), // not blocked
			RestrictPublicBuckets: awssdk.Bool(true),
		},
		versioning:     s3types.BucketVersioningStatusEnabled,
		loggingEnabled: true,
	})
	got, err := p.AuditStorage(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Type != cloud.BucketPublicAccess {
		t.Errorf("expected one public-access finding, got %v", got)
	}
}

func TestAuditStorage_UnencryptedBucket(t *testing.T) {
	p := newStorageProvider(&mockS3{
		buckets: []s3types.Bucket{{Name: awssdk.String("plaintext")}},
		pubAccessBlock: &s3types.PublicAccessBlockConfiguration{
			BlockPublicAcls: awssdk.Bool(true), IgnorePublicAcls: awssdk.Bool(true),
			BlockPublicPolicy: awssdk.Bool(true), RestrictPublicBuckets: awssdk.Bool(true),
		},
		encErr:         &apiErr{code: "ServerSideEncryptionConfigurationNotFoundError"},
		versioning:     s3types.BucketVersioningStatusEnabled,
		loggingEnabled: true,
	})
	got, err := p.AuditStorage(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Type != cloud.BucketUnencrypted || got[0].Severity != cloud.SeverityHigh {
		t.Errorf("expected one high unencrypted finding, got %v", got)
	}
}

func TestAuditStorage_NoVersioning(t *testing.T) {
	p := newStorageProvider(&mockS3{
		buckets: []s3types.Bucket{{Name: awssdk.String("no-version")}},
		pubAccessBlock: &s3types.PublicAccessBlockConfiguration{
			BlockPublicAcls: awssdk.Bool(true), IgnorePublicAcls: awssdk.Bool(true),
			BlockPublicPolicy: awssdk.Bool(true), RestrictPublicBuckets: awssdk.Bool(true),
		},
		versioning:     s3types.BucketVersioningStatusSuspended,
		loggingEnabled: true,
	})
	got, err := p.AuditStorage(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Type != cloud.BucketNoVersioning || got[0].Severity != cloud.SeverityMedium {
		t.Errorf("expected one medium no-versioning finding, got %v", got)
	}
}

func TestAuditStorage_NoLogging(t *testing.T) {
	p := newStorageProvider(&mockS3{
		buckets: []s3types.Bucket{{Name: awssdk.String("no-logs")}},
		pubAccessBlock: &s3types.PublicAccessBlockConfiguration{
			BlockPublicAcls: awssdk.Bool(true), IgnorePublicAcls: awssdk.Bool(true),
			BlockPublicPolicy: awssdk.Bool(true), RestrictPublicBuckets: awssdk.Bool(true),
		},
		versioning:     s3types.BucketVersioningStatusEnabled,
		loggingEnabled: false,
	})
	got, err := p.AuditStorage(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Type != cloud.BucketNoLogging || got[0].Severity != cloud.SeverityLow {
		t.Errorf("expected one low no-logging finding, got %v", got)
	}
}

func TestBucketRegion(t *testing.T) {
	tests := []struct {
		name string
		loc  s3types.BucketLocationConstraint
		want string
	}{
		{"empty location maps to us-east-1", "", "us-east-1"},
		{"named region passes through", s3types.BucketLocationConstraintEuWest1, "eu-west-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newStorageProvider(&mockS3{location: tt.loc})
			got, err := p.bucketRegion(context.Background(), p.s3, "any")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsS3ErrorCode(t *testing.T) {
	if !isS3ErrorCode(&apiErr{code: "NoSuchBucket"}, "NoSuchBucket") {
		t.Error("expected match on code")
	}
	if isS3ErrorCode(&apiErr{code: "Other"}, "NoSuchBucket") {
		t.Error("expected no match on different code")
	}
	if isS3ErrorCode(errors.New("plain"), "NoSuchBucket") {
		t.Error("plain error should not match")
	}
}
