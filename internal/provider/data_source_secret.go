package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/tiwood/terraform-provider-azurekeyvault/internal/provider/parse"
	"github.com/tiwood/terraform-provider-azurekeyvault/internal/provider/tags"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceSecret() *schema.Resource {
	return &schema.Resource{
		// This description is used by the documentation generator and the language server.
		Description: "Sample data source in the Terraform provider scaffolding.",

		ReadContext: dataSourceSecretRead,

		Schema: map[string]*schema.Schema{
			"key_vault_name": {
				Description: "Sample attribute.",
				Type:        schema.TypeString,
				Required:    true,
			},
			"name": {
				Description: "Sample attribute.",
				Type:        schema.TypeString,
				Required:    true,
			},
			"value": {
				Description: "Sample attribute.",
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
			},
			"content_type": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"not_before": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"not_after": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"version": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"versionless_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"tags": tags.SchemaDataSource(),
		},
	}
}

func dataSourceSecretRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(keyvault.BaseClient)

	secretName := d.Get("name").(string)
	keyVaultName := d.Get("key_vault_name").(string)
	keyVaultURI := fmt.Sprintf("https://%s.vault.azure.net", keyVaultName)

	r, err := client.GetSecret(ctx, keyVaultURI, secretName, "")
	if err != nil {
		diags = append(diags, diag.Errorf("unable to read secret: %v", err)...)
		return diags
	}

	parsedFromResp, err := parse.ParseNestedItemID(*r.ID)
	if err != nil {
		diags = append(diags, diag.Errorf("unable to parse Key Vault ID: %v", err)...)
		return diags
	}

	d.SetId(*r.ID)
	d.Set("value", r.Value)
	d.Set("version", parsedFromResp.Version)
	d.Set("content_type", r.ContentType)
	d.Set("versionless_id", parsedFromResp.VersionlessID())

	if attributes := r.Attributes; attributes != nil {
		if v := attributes.NotBefore; v != nil {
			d.Set("not_before", time.Time(*v).Format(time.RFC3339))
		}

		if v := attributes.Expires; v != nil {
			d.Set("not_after", time.Time(*v).Format(time.RFC3339))
		}
	}


	return tags.FlattenAndSet(d, r.Tags)
}
