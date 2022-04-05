package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/tiwood/terraform-provider-azurekeyvault/internal/provider/parse"
	"github.com/tiwood/terraform-provider-azurekeyvault/internal/provider/tags"

	//"github.com/tiwood/terraform-provider-azurekeyvault/internal/provider/tags"
	"github.com/tiwood/terraform-provider-azurekeyvault/internal/provider/utils"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/go-autorest/autorest/date"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// var diags diag.Diagnostics

func resourceSecret() *schema.Resource {
	return &schema.Resource{
		// This description is used by the documentation generator and the language server.
		Description: "Sample resource in the Terraform provider scaffolding.",

		CreateContext: resourceSecretCreate,
		ReadContext:   resourceSecretRead,
		UpdateContext: resourceSecretUpdate,
		DeleteContext: resourceSecretDelete,

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
				Required:    true,
				Sensitive:   true,
			},
			"content_type": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"not_before": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"not_after": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"version": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"versionless_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"purge_on_destroy": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"tags": tags.Schema(),
		},
	}
}

func resourceSecretCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(keyvault.BaseClient)
	secretName := d.Get("name").(string)
	secretValue := d.Get("value").(string)
	keyVaultName := d.Get("key_vault_name").(string)
	keyVaultURI := fmt.Sprintf("https://%s.vault.azure.net", keyVaultName)
	contentType := d.Get("content_type").(string)
	tagsVal := d.Get("tags").(map[string]interface{})

	params := keyvault.SecretSetParameters{
		Value:            &secretValue,
		ContentType:      utils.String(contentType),
		Tags:             tags.Expand(tagsVal),
		SecretAttributes: &keyvault.SecretAttributes{},
	}

	if v, ok := d.GetOk("not_before"); ok {
		notBeforeDate, _ := time.Parse(time.RFC3339, v.(string))
		notBeforeUnixTime := date.UnixTime(notBeforeDate)
		params.SecretAttributes.NotBefore = &notBeforeUnixTime
	}

	if v, ok := d.GetOk("not_after"); ok {
		expirationDate, _ := time.Parse(time.RFC3339, v.(string))
		expirationUnixTime := date.UnixTime(expirationDate)
		params.SecretAttributes.Expires = &expirationUnixTime
	}

	r, err := client.SetSecret(ctx, keyVaultURI, secretName, params)
	if err != nil {
		diags = append(diags, diag.Errorf("unable to create secret: %v", err)...)
		return diags
	}

	d.SetId(*r.ID)

	return resourceSecretRead(ctx, d, meta)
}

func resourceSecretRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(keyvault.BaseClient)

	parsedFromState, err := parse.ParseNestedItemID(d.Id())
	if err != nil {
		diags = append(diags, diag.Errorf("unable to parse Key Vault ID: %v", err)...)
		return diags
	}

	r, err := client.GetSecret(ctx, parsedFromState.KeyVaultBaseUrl, parsedFromState.Name, "")
	if err != nil {
		diags = append(diags, diag.Errorf("unable to read secret: %v", err)...)
		return diags
	}

	parsedFromResp, err := parse.ParseNestedItemID(*r.ID)
	if err != nil {
		diags = append(diags, diag.Errorf("unable to parse Key Vault ID: %v", err)...)
		return diags
	}

	d.Set("name", parsedFromResp.Name)
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

func resourceSecretUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(keyvault.BaseClient)
	secretValue := d.Get("value").(string)
	contentType := d.Get("content_type").(string)
	tagsVal := d.Get("tags").(map[string]interface{})

	parsedFromState, err := parse.ParseNestedItemID(d.Id())
	if err != nil {
		diags = append(diags, diag.Errorf("unable to parse Key Vault ID: %v", err)...)
		return diags
	}

	secretAttributes := &keyvault.SecretAttributes{}

	if v, ok := d.GetOk("not_before"); ok {
		notBeforeDate, _ := time.Parse(time.RFC3339, v.(string))
		notBeforeUnixTime := date.UnixTime(notBeforeDate)
		secretAttributes.NotBefore = &notBeforeUnixTime
	}

	if v, ok := d.GetOk("not_after"); ok {
		expirationDate, _ := time.Parse(time.RFC3339, v.(string))
		expirationUnixTime := date.UnixTime(expirationDate)
		secretAttributes.Expires = &expirationUnixTime
	}

	// if the secret value has changed, we have to use the `SetSecret` method
	if d.HasChange("value") {
		params := keyvault.SecretSetParameters{
			Value:            &secretValue,
			ContentType:      utils.String(contentType),
			Tags:             tags.Expand(tagsVal),
			SecretAttributes: secretAttributes,
		}

		_, err := client.SetSecret(ctx, parsedFromState.KeyVaultBaseUrl, parsedFromState.Name, params)
		if err != nil {
			diags = append(diags, diag.Errorf("unable to create secret: %v", err)...)
			return diags
		}
	}

	// if the secret value is not changed, we use the `UpdateSecret` method
	if !d.HasChange("value") {
		params := &keyvault.SecretUpdateParameters{
			ContentType:      &contentType,
			Tags:             tags.Expand(tagsVal),
			SecretAttributes: secretAttributes,
		}
		_, err := client.UpdateSecret(ctx, parsedFromState.KeyVaultBaseUrl, parsedFromState.Name, "", *params)
		if err != nil {
			diags = append(diags, diag.Errorf("unable to update secret: %v", err)...)
			return diags
		}
	}

	return resourceSecretRead(ctx, d, meta)
}

func resourceSecretDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(keyvault.BaseClient)

	timeout, ok := ctx.Deadline()
	if !ok {
		diags = append(diags, diag.Errorf("context is missing a timeout")...)
		return diags
	}

	parsedFromState, err := parse.ParseNestedItemID(d.Id())
	if err != nil {
		diags = append(diags, diag.Errorf("unable to parse Key Vault ID: %v", err)...)
		return diags
	}

	_, err = client.DeleteSecret(ctx, parsedFromState.KeyVaultBaseUrl, parsedFromState.Name)
	if err != nil {
		diags = append(diags, diag.Errorf("unable to delete Key Vault secret: %v", err)...)
		return diags
	}

	shouldPurge := d.Get("purge_on_destroy").(bool)
	if shouldPurge {
		stateChangeConf := &resource.StateChangeConf{
			Pending:                   []string{"SecretFound"},
			Target:                    []string{"SecretNotFound"},
			ContinuousTargetOccurence: 3,
			PollInterval:              5 * time.Second,
			Timeout:                   time.Until(timeout),
			Refresh:                   resourceSecretDeleteRefresh(ctx, d, client),
		}

		if _, err := stateChangeConf.WaitForStateContext(ctx); err != nil {
			diags = append(diags, diag.Errorf("failed while waiting for secret deletion: %v", err)...)
			return diags
		}

		_, err := client.PurgeDeletedSecret(ctx, parsedFromState.KeyVaultBaseUrl, parsedFromState.Name)
		if err != nil {
			diags = append(diags, diag.Errorf("unable to purge Key Vault secret: %v", err)...)
			return diags
		}
	}

	return nil
}

func resourceSecretDeleteRefresh(ctx context.Context, d *schema.ResourceData, client keyvault.BaseClient) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		parsedFromState, err := parse.ParseNestedItemID(d.Id())
		if err != nil {
			return nil, "ParsingError", err
		}

		r, err := client.GetSecret(ctx, parsedFromState.KeyVaultBaseUrl, parsedFromState.Name, "")
		if err != nil {
			tflog.Debug(ctx, fmt.Sprintf("Waiting for secret deletion, current error is: %v", err.Error()))
			if strings.Contains(err.Error(), "SecretNotFound") {
				tflog.Debug(ctx, "Waiting for secret deletion completed.")
				return r, "SecretNotFound", nil
			}
		}

		return nil, "SecretFound", nil
	}
}