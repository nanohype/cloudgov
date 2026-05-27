package gcp

import (
	"context"
	"fmt"
	"os"

	"cloud.google.com/go/logging/logadmin"
	gcsstorage "cloud.google.com/go/storage"
	bigqueryv2 "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/certificatemanager/v1"
	"google.golang.org/api/cloudfunctions/v1"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/container/v1"
	googleiam "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	runv1 "google.golang.org/api/run/v1"
	"google.golang.org/api/run/v2"
	"google.golang.org/api/sqladmin/v1beta4"
	cstorage "google.golang.org/api/storage/v1"
)

// Provider implements Matlock provider interfaces for GCP.
//
// The GCP Go SDK exposes chained call builders (svc.Projects.GetIamPolicy(...).Context(ctx).Do())
// that are awkward to mock directly. We hide that behind narrow per-domain
// interfaces (crmAPI, googleIAMAPI, etc.) declared in their owning files;
// production code wires adapters that wrap the real services, tests inject
// mocks satisfying the same interfaces.
type Provider struct {
	projectID          string
	opts               []option.ClientOption
	crm                crmAPI
	googleIAM          googleIAMAPI
	compute            computeAPI
	certManager        certManagerAPI
	bigquery           bigqueryAPI
	iamServiceAccounts iamServiceAccountsAPI
	sqladmin           sqladminAPI
	container          containerAPI
	cloudRunV2         cloudRunV2API
	cloudRunV1         cloudRunV1API
	cloudFunctions     cloudFunctionsAPI
	gcsREST            gcsRESTAPI
	// newLogAdmin builds a logAdminAPI for the given project. Production wires
	// to *logadmin.Client; tests override with a fake.
	newLogAdmin func(ctx context.Context, projectID string) (logAdminAPI, error)
	// newGCS builds a gcsAPI. Production wires to *storage.Client; tests override.
	newGCS func(ctx context.Context) (gcsAPI, error)
}

// New creates a GCP provider using Application Default Credentials.
// projectID can be set explicitly; if empty it is read from GOOGLE_CLOUD_PROJECT.
func New(ctx context.Context, projectID string) (*Provider, error) {
	if projectID == "" {
		projectID = os.Getenv("GOOGLE_CLOUD_PROJECT")
		if projectID == "" {
			projectID = os.Getenv("GCLOUD_PROJECT")
		}
	}
	p := &Provider{projectID: projectID}

	crmSvc, err := cloudresourcemanager.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("cloudresourcemanager client: %w", err)
	}
	p.crm = &crmAdapter{svc: crmSvc}

	iamSvc, err := googleiam.NewService(ctx, option.WithScopes("https://www.googleapis.com/auth/cloud-platform"))
	if err != nil {
		return nil, fmt.Errorf("iam client: %w", err)
	}
	p.googleIAM = &googleIAMAdapter{svc: iamSvc}
	p.iamServiceAccounts = &iamServiceAccountsAdapter{svc: iamSvc}

	computeSvc, err := compute.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("compute client: %w", err)
	}
	p.compute = &computeAdapter{svc: computeSvc}

	certSvc, err := certificatemanager.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("certificate manager client: %w", err)
	}
	p.certManager = &certManagerAdapter{svc: certSvc}

	bqSvc, err := bigqueryv2.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("bigquery client: %w", err)
	}
	p.bigquery = &bigqueryAdapter{svc: bqSvc}

	sqlSvc, err := sqladmin.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("sqladmin client: %w", err)
	}
	p.sqladmin = &sqladminAdapter{svc: sqlSvc}

	containerSvc, err := container.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("container client: %w", err)
	}
	p.container = &containerAdapter{svc: containerSvc}

	runSvc, err := run.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("cloud run client: %w", err)
	}
	p.cloudRunV2 = &cloudRunV2Adapter{svc: runSvc}

	gcsRESTSvc, err := cstorage.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("storage v1 client: %w", err)
	}
	p.gcsREST = &gcsRESTAdapter{svc: gcsRESTSvc}

	runV1Svc, err := runv1.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("cloud run v1 client: %w", err)
	}
	p.cloudRunV1 = &cloudRunV1Adapter{svc: runV1Svc}

	cfSvc, err := cloudfunctions.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("cloud functions client: %w", err)
	}
	p.cloudFunctions = &cloudFunctionsAdapter{svc: cfSvc}

	p.newLogAdmin = func(ctx context.Context, projectID string) (logAdminAPI, error) {
		client, err := logadmin.NewClient(ctx, projectID)
		if err != nil {
			return nil, err
		}
		return &logAdminAdapter{client: client}, nil
	}

	p.newGCS = func(ctx context.Context) (gcsAPI, error) {
		client, err := gcsstorage.NewClient(ctx, p.opts...)
		if err != nil {
			return nil, err
		}
		return &gcsAdapter{client: client}, nil
	}

	return p, nil
}

// Name returns the provider identifier.
func (p *Provider) Name() string { return "gcp" }

// Detect returns true when GCP credentials are present in the environment.
func (p *Provider) Detect(_ context.Context) bool {
	if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "" {
		return true
	}
	if os.Getenv("GOOGLE_CLOUD_PROJECT") != "" || os.Getenv("GCLOUD_PROJECT") != "" {
		return true
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		adc := home + "/.config/gcloud/application_default_credentials.json"
		if _, err := os.Stat(adc); err == nil {
			return true
		}
	}
	return false
}
