package provider

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var diags diag.Diagnostics

func init() {
	schema.DescriptionKind = schema.StringMarkdown
}

func New(version string) func() *schema.Provider {
	return func() *schema.Provider {
		p := &schema.Provider{
			Schema: map[string]*schema.Schema{
				"tenant_id": {
					Description: "The Tenant ID should be used. This can also be sourced from the `KEYVAULT_TENANT_ID` Environment Variable.",
					Type:        schema.TypeString,
					Optional:    true,
					DefaultFunc: schema.EnvDefaultFunc("KEYVAULT_TENANT_ID", nil),
				},
				"client_id": {
					Description: "The Client ID which should be used. This can also be sourced from the `KEYVAULT_CLIENT_ID` Environment Variable.",
					Type:        schema.TypeString,
					Optional:    true,
					DefaultFunc: schema.EnvDefaultFunc("KEYVAULT_CLIENT_ID", nil),
				},
				"client_secret": {
					Description: "The Client Secret which should be used. This can also be sourced from the `KEYVAULT_CLIENT_SECRET` Environment Variable.",
					Type:        schema.TypeString,
					Optional:    true,
					Sensitive:   true,
					DefaultFunc: schema.EnvDefaultFunc("KEYVAULT_CLIENT_SECRET", nil),
				},
			},
			DataSourcesMap: map[string]*schema.Resource{
				"azurekeyvault_secret": dataSourceSecret(),
			},
			ResourcesMap: map[string]*schema.Resource{
				"azurekeyvault_certificate": resourceCertificate(),
				"azurekeyvault_secret":      resourceSecret(),
			},
		}

		p.ConfigureContextFunc = configure(version, p)

		return p
	}
}

func configure(version string, p *schema.Provider) func(context.Context, *schema.ResourceData) (interface{}, diag.Diagnostics) {
	return func(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
		tenantID := d.Get("tenant_id").(string)
		clientID := d.Get("client_id").(string)
		clientSecret := d.Get("client_secret").(string)

		clientCredentialCfg := auth.NewClientCredentialsConfig(clientID, clientSecret, tenantID)
		clientCredentialCfg.Resource = "https://vault.azure.net"
		authorizer, err := clientCredentialCfg.Authorizer()
		if err != nil {
			diags = append(diags, diag.Errorf("unable to create autorest authorizer: %v", err)...)
			return nil, diags
		}

		kvClient := keyvault.New()
		kvClient.Authorizer = authorizer

		return kvClient, diags
	}
}
