package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/tiwood/terraform-provider-azurekeyvault/internal/provider/parse"
	"github.com/tiwood/terraform-provider-azurekeyvault/internal/provider/tags"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceSecret() *schema.Resource {
	return &schema.Resource{
		Description: "Use this data source to access information about an existing Key Vault Secret.",

		ReadContext: dataSourceSecretRead,

		Schema: map[string]*schema.Schema{
			"key_vault_name": {
				Description: "The name of the target Key Vault.",
				Type:        schema.TypeString,
				Required:    true,
			},
			"name": {
				Description: "Specifies the name of the Key Vault Secret.",
				Type:        schema.TypeString,
				Required:    true,
			},
			"value": {
				Description: "Specifies the value of the Key Vault Secret.",
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
			},
			"content_type": {
				Description: "Specifies the content type for the Key Vault Secret.",
				Type:        schema.TypeString,
				Computed:    true,
			},
			"not_before": {
				Description: "Secret not usable before the provided UTC datetime `(Y-m-d'T'H:M:S'Z')`",
				Type:        schema.TypeString,
				Computed:    true,
			},
			"not_after": {
				Description: "Secret not usable after the provided UTC datetime `(Y-m-d'T'H:M:S'Z')`",
				Type:        schema.TypeString,
				Computed:    true,
			},
			"version": {
				Description: "The current version of the Key Vault Secret.",
				Type:        schema.TypeString,
				Computed:    true,
			},
			"versionless_id": {
				Description: "The Base ID of the Key Vault Secret.",
				Type:        schema.TypeString,
				Computed:    true,
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
