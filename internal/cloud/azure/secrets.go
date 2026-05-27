package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/stxkxs/matlock/internal/cloud"
	"github.com/stxkxs/matlock/internal/secrets"
)

// webAppsAPI is the narrow App Service surface used by this package.
type webAppsAPI interface {
	List(ctx context.Context) ([]*armappservice.Site, error)
	ListApplicationSettings(ctx context.Context, resourceGroup, name string) (map[string]*string, error)
}

type webAppsAdapter struct{ client *armappservice.WebAppsClient }

func (a *webAppsAdapter) List(ctx context.Context) ([]*armappservice.Site, error) {
	var out []*armappservice.Site
	pager := a.client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return out, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

func (a *webAppsAdapter) ListApplicationSettings(ctx context.Context, rg, name string) (map[string]*string, error) {
	resp, err := a.client.ListApplicationSettings(ctx, rg, name, nil)
	if err != nil {
		return nil, err
	}
	if resp.Properties == nil {
		return nil, nil
	}
	return resp.Properties, nil
}

// ScanSecrets checks App Service settings and Function App settings for secrets.
func (p *Provider) ScanSecrets(ctx context.Context) ([]cloud.SecretFinding, error) {
	var findings []cloud.SecretFinding

	if f, err := p.scanWebAppSecrets(ctx); err != nil {
		return nil, fmt.Errorf("web app secrets: %w", err)
	} else {
		findings = append(findings, f...)
	}

	return findings, nil
}

func (p *Provider) scanWebAppSecrets(ctx context.Context) ([]cloud.SecretFinding, error) {
	apps, err := p.webApps.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list web apps: %w", err)
	}

	var findings []cloud.SecretFinding
	for _, app := range apps {
		if app.Name == nil {
			continue
		}
		appName := *app.Name
		rg := resourceGroupFromID(app.ID)
		if rg == "" {
			continue
		}

		resourceType := "app_service_setting"
		resourcePrefix := "app-service:"
		if app.Kind != nil && strings.Contains(*app.Kind, "functionapp") {
			resourceType = "function_app_setting"
			resourcePrefix = "function-app:"
		}

		settings, err := p.webApps.ListApplicationSettings(ctx, rg, appName)
		if err != nil {
			continue
		}
		location := ""
		if app.Location != nil {
			location = *app.Location
		}
		for key, val := range settings {
			if val == nil {
				continue
			}
			for _, m := range secrets.Scan(*val) {
				findings = append(findings, cloud.SecretFinding{
					Severity:     m.Severity,
					Type:         m.Type,
					Provider:     "azure",
					Resource:     resourcePrefix + appName,
					ResourceType: resourceType,
					Region:       location,
					Key:          key,
					Match:        secrets.Redact(m.Value),
					Detail:       fmt.Sprintf("%s found in %s%s setting %q", m.Name, resourcePrefix, appName, key),
					Remediation:  fmt.Sprintf("Move secret from app setting %q to Key Vault and use Key Vault reference", key),
				})
			}
		}
	}
	return findings, nil
}

func resourceGroupFromID(id *string) string {
	if id == nil {
		return ""
	}
	parts := strings.Split(*id, "/")
	for i, part := range parts {
		if strings.EqualFold(part, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
