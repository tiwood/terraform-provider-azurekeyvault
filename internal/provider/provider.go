package provider

import (
	"context"

	//"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var diags diag.Diagnostics

func init() {
	// Set descriptions to support markdown syntax, this will be used in document generation
	// and the language server.
	schema.DescriptionKind = schema.StringMarkdown

	// Customize the content of descriptions when output. For example you can add defaults on
	// to the exported descriptions if present.
	// schema.SchemaDescriptionBuilder = func(s *schema.Schema) string {
	// 	desc := s.Description
	// 	if s.Default != nil {
	// 		desc += fmt.Sprintf(" Defaults to `%v`.", s.Default)
	// 	}
	// 	return strings.TrimSpace(desc)
	// }
}

func New(version string) func() *schema.Provider {
	return func() *schema.Provider {
		p := &schema.Provider{
			Schema: map[string]*schema.Schema{
				"tenant_id": {
					Type:        schema.TypeString,
					Optional:    true,
					DefaultFunc: schema.EnvDefaultFunc("KEYVAULT_TENANT_ID", nil),
				},
				"client_id": {
					Type:        schema.TypeString,
					Optional:    true,
					DefaultFunc: schema.EnvDefaultFunc("KEYVAULT_CLIENT_ID", nil),
				},
				"client_secret": {
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
				"azurekeyvault_secret": resourceSecret(),
			},
		}

		p.ConfigureContextFunc = configure(version, p)

		return p
	}
}

// type apiClient struct {
// 	KeyVault *keyvault.Client
// }

func configure(version string, p *schema.Provider) func(context.Context, *schema.ResourceData) (interface{}, diag.Diagnostics) {
	return func(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
		// Setup a User-Agent for your API client (replace the provider name for yours):
		// userAgent := p.UserAgent("terraform-provider-scaffolding", version)
		// TODO: myClient.UserAgent = userAgent

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
