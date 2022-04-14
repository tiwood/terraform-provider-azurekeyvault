package provider

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"strings"
	"time"

	"github.com/tiwood/terraform-provider-azurekeyvault/internal/provider/parse"
	"github.com/tiwood/terraform-provider-azurekeyvault/internal/provider/set"
	"github.com/tiwood/terraform-provider-azurekeyvault/internal/provider/suppress"
	"github.com/tiwood/terraform-provider-azurekeyvault/internal/provider/tags"
	"github.com/tiwood/terraform-provider-azurekeyvault/internal/provider/utils"

	//"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceCertificate() *schema.Resource {
	return &schema.Resource{
		// This description is used by the documentation generator and the language server.
		Description: "Sample resource in the Terraform provider scaffolding.",

		CreateContext: resourceCertificateCreate,
		ReadContext:   resourceCertificateRead,
		UpdateContext: resourceCertificateUpdate,
		DeleteContext: resourceCertificateDelete,

		Schema: map[string]*schema.Schema{
			"key_vault_name": {
				Description: "Sample attribute.",
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
			},
			"name": {
				Description: "Sample attribute.",
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
			},
			"certificate": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				AtLeastOneOf: []string{
					"certificate_policy",
					"certificate",
				},
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"contents": {
							Type:         schema.TypeString,
							Required:     true,
							ForceNew:     true,
							Sensitive:    true,
							ValidateFunc: validation.StringIsNotEmpty,
						},
						"password": {
							Type:      schema.TypeString,
							Optional:  true,
							ForceNew:  true,
							Sensitive: true,
						},
					},
				},
			},
			"certificate_policy": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				ForceNew: true,
				AtLeastOneOf: []string{
					"certificate_policy",
					"certificate",
				},
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"issuer_parameters": {
							Type:     schema.TypeList,
							Required: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:     schema.TypeString,
										Required: true,
										ForceNew: true,
									},
								},
							},
						},
						"key_properties": {
							Type:     schema.TypeList,
							Required: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"curve": {
										Type:     schema.TypeString,
										Optional: true,
										Computed: true,
										ForceNew: true,
										ValidateFunc: validation.StringInSlice([]string{
											string(keyvault.P256),
											string(keyvault.P256K),
											string(keyvault.P384),
											string(keyvault.P521),
										}, false),
									},
									"exportable": {
										Type:     schema.TypeBool,
										Required: true,
										ForceNew: true,
									},
									"key_size": {
										Type:     schema.TypeInt,
										Optional: true,
										Computed: true,
										ForceNew: true,
										ValidateFunc: validation.IntInSlice([]int{
											256,
											384,
											521,
											2048,
											3072,
											4096,
										}),
									},
									"key_type": {
										Type:     schema.TypeString,
										Required: true,
										ForceNew: true,
										ValidateFunc: validation.StringInSlice([]string{
											string(keyvault.EC),
											string(keyvault.ECHSM),
											string(keyvault.RSA),
											string(keyvault.RSAHSM),
											string(keyvault.Oct),
										}, false),
										DiffSuppressFunc: suppress.CaseDifference,
									},
									"reuse_key": {
										Type:     schema.TypeBool,
										Required: true,
										ForceNew: true,
									},
								},
							},
						},
						"lifetime_action": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"action": {
										Type:     schema.TypeList,
										Required: true,
										MaxItems: 1,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"action_type": {
													Type:     schema.TypeString,
													Required: true,
													ForceNew: true,
													ValidateFunc: validation.StringInSlice([]string{
														string(keyvault.AutoRenew),
														string(keyvault.EmailContacts),
													}, false),
												},
											},
										},
									},
									//lintignore:XS003
									"trigger": {
										Type:     schema.TypeList,
										Required: true,
										MaxItems: 1,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"days_before_expiry": {
													Type:     schema.TypeInt,
													Optional: true,
													ForceNew: true,
												},
												"lifetime_percentage": {
													Type:     schema.TypeInt,
													Optional: true,
													ForceNew: true,
												},
											},
										},
									},
								},
							},
						},
						"secret_properties": {
							Type:     schema.TypeList,
							Required: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"content_type": {
										Type:     schema.TypeString,
										Required: true,
										ForceNew: true,
									},
								},
							},
						},

						"x509_certificate_properties": {
							Type:     schema.TypeList,
							Optional: true,
							Computed: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"extended_key_usage": {
										Type:     schema.TypeList,
										Optional: true,
										Computed: true,
										ForceNew: true,
										Elem: &schema.Schema{
											Type:         schema.TypeString,
											ValidateFunc: validation.StringIsNotEmpty,
										},
									},
									"key_usage": {
										Type:     schema.TypeSet,
										Required: true,
										ForceNew: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
											ValidateFunc: validation.StringInSlice([]string{
												string(keyvault.CRLSign),
												string(keyvault.DataEncipherment),
												string(keyvault.DecipherOnly),
												string(keyvault.DigitalSignature),
												string(keyvault.EncipherOnly),
												string(keyvault.KeyAgreement),
												string(keyvault.KeyCertSign),
												string(keyvault.KeyEncipherment),
												string(keyvault.NonRepudiation),
											}, false),
										},
									},
									"subject": {
										Type:     schema.TypeString,
										Required: true,
										ForceNew: true,
									},
									"subject_alternative_names": {
										Type:     schema.TypeList,
										Optional: true,
										ForceNew: true,
										Computed: true,
										MaxItems: 1,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"emails": {
													Type:     schema.TypeSet,
													Optional: true,
													ForceNew: true,
													Elem: &schema.Schema{
														Type: schema.TypeString,
													},
													Set: schema.HashString,
													AtLeastOneOf: []string{
														"certificate_policy.0.x509_certificate_properties.0.subject_alternative_names.0.emails",
														"certificate_policy.0.x509_certificate_properties.0.subject_alternative_names.0.dns_names",
														"certificate_policy.0.x509_certificate_properties.0.subject_alternative_names.0.upns",
													},
												},
												"dns_names": {
													Type:     schema.TypeSet,
													Optional: true,
													ForceNew: true,
													Elem: &schema.Schema{
														Type: schema.TypeString,
													},
													Set: schema.HashString,
													AtLeastOneOf: []string{
														"certificate_policy.0.x509_certificate_properties.0.subject_alternative_names.0.emails",
														"certificate_policy.0.x509_certificate_properties.0.subject_alternative_names.0.dns_names",
														"certificate_policy.0.x509_certificate_properties.0.subject_alternative_names.0.upns",
													},
												},
												"upns": {
													Type:     schema.TypeSet,
													Optional: true,
													ForceNew: true,
													Elem: &schema.Schema{
														Type: schema.TypeString,
													},
													Set: schema.HashString,
													AtLeastOneOf: []string{
														"certificate_policy.0.x509_certificate_properties.0.subject_alternative_names.0.emails",
														"certificate_policy.0.x509_certificate_properties.0.subject_alternative_names.0.dns_names",
														"certificate_policy.0.x509_certificate_properties.0.subject_alternative_names.0.upns",
													},
												},
											},
										},
									},
									"validity_in_months": {
										Type:     schema.TypeInt,
										Required: true,
										ForceNew: true,
									},
								},
							},
						},
					},
				},
			},
			"certificate_attribute": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"created": {
							Type:     schema.TypeString,
							Computed: true,
						},

						"enabled": {
							Type:     schema.TypeBool,
							Computed: true,
						},

						"expires": {
							Type:     schema.TypeString,
							Computed: true,
						},

						"not_before": {
							Type:     schema.TypeString,
							Computed: true,
						},

						"recovery_level": {
							Type:     schema.TypeString,
							Computed: true,
						},

						"updated": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
			"version": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"secret_id": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"versionless_id": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"versionless_secret_id": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"certificate_data": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"certificate_data_base64": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"thumbprint": {
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

func resourceCertificateCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(keyvault.BaseClient)
	keyVaultName := d.Get("key_vault_name").(string)
	name := d.Get("name").(string)
	keyVaultURI := fmt.Sprintf("https://%s.vault.azure.net", keyVaultName)
	tagsVal := d.Get("tags").(map[string]interface{})
	policy, err := expandKeyVaultCertificatePolicy(d)
	if err != nil {
		diags = append(diags, diag.Errorf("unable to expand certificate policy: %v", err)...)
		return diags
	}

	if v, ok := d.GetOk("certificate"); ok {
		// Import
		certificate := expandKeyVaultCertificate(v)

		if err != nil {
			diags = append(diags, diag.Errorf("unable to expand certificate: %v", err)...)
			return diags
		}
		params := keyvault.CertificateImportParameters{
			Base64EncodedCertificate: utils.String(certificate.CertificateData),
			Password:                 utils.String(certificate.CertificatePassword),
			CertificatePolicy:        policy,
			Tags:                     tags.Expand(tagsVal),
		}
		if _, err := client.ImportCertificate(ctx, keyVaultURI, name, params); err != nil {
			diags = append(diags, diag.Errorf("unable to import certificate: %v", err)...)
			return diags
		}
	} else {
		// Create new
		params := keyvault.CertificateCreateParameters{
			CertificatePolicy: policy,
			Tags:              tags.Expand(tagsVal),
		}
		if _, err := client.CreateCertificate(ctx, keyVaultURI, name, params); err != nil {
			diags = append(diags, diag.Errorf("unable to create certificate: %v", err)...)
			return diags
		}
		stateChangeConf := &resource.StateChangeConf{
			Pending:    []string{"Provisioning"},
			Target:     []string{"Ready"},
			Refresh:    keyVaultCertificateCreationRefreshFunc(ctx, &client, keyVaultURI, name),
			MinTimeout: 15 * time.Second,
			Timeout:    d.Timeout(schema.TimeoutCreate),
		}
		// It has been observed that at least one certificate issuer responds to a request with manual processing by issuer staff. SLA's may differ among issuers.
		// The total create timeout duration is divided by a modified poll interval of 30s to calculate the number of times to allow not found instead of the default 20.
		// Using math.Floor, the calculation will err on the lower side of the creation timeout, so as to return before the overall create timeout occurs.
		if policy != nil && policy.IssuerParameters != nil && policy.IssuerParameters.Name != nil && *policy.IssuerParameters.Name != "Self" {
			stateChangeConf.PollInterval = 30 * time.Second
			stateChangeConf.NotFoundChecks = int(math.Floor(float64(stateChangeConf.Timeout) / float64(stateChangeConf.PollInterval)))
		}

		if _, err := stateChangeConf.WaitForStateContext(ctx); err != nil {
			diags = append(diags, diag.Errorf("waiting for Certificate %q in Vault %q to become available: %s", name, keyVaultURI, err)...)
			return diags
		}
	}

	resp, err := client.GetCertificate(ctx, *&keyVaultURI, name, "")
	if err != nil {
		diags = append(diags, diag.Errorf("unable to verify the successful creation/import of the certificate: %v", err)...)
		return diags
	}

	d.SetId(*resp.ID)

	return resourceCertificateRead(ctx, d, meta)
}

func resourceCertificateRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(keyvault.BaseClient)

	parsedFromState, err := parse.ParseNestedItemID(d.Id())
	if err != nil {
		diags = append(diags, diag.Errorf("unable to parse Key Vault ID: %v", err)...)
		return diags
	}

	r, err := client.GetCertificate(ctx, parsedFromState.KeyVaultBaseUrl, parsedFromState.Name, "")
	if err != nil {
		diags = append(diags, diag.Errorf("unable to read certificate: %v", err)...)
		return diags
	}

	parsedFromResp, err := parse.ParseNestedItemID(*r.ID)
	if err != nil {
		diags = append(diags, diag.Errorf("unable to parse Key Vault ID: %v", err)...)
		return diags
	}

	certificatePolicy := flattenKeyVaultCertificatePolicy(r.Policy, r.Cer)
	if err := d.Set("certificate_policy", certificatePolicy); err != nil {
		diags = append(diags, diag.Errorf("failed setting certificate_policy: %v", err)...)
		return diags
	}

	if err := d.Set("certificate_attribute", flattenKeyVaultCertificateAttribute(r.Attributes)); err != nil {
		diags = append(diags, diag.Errorf("failed setting certificate_attribute: %v", err)...)
		return diags
	}

	d.Set("name", parsedFromResp.Name)
	d.Set("version", parsedFromResp.Version)
	d.Set("versionless_id", parsedFromResp.VersionlessID())
	d.Set("secret_id", r.Sid)

	if r.Sid != nil {
		secretId, err := parse.ParseNestedItemID(*r.Sid)
		if err != nil {
			diags = append(diags, diag.Errorf("unable to parse Key Vault ID: %v", err)...)
			return diags
		}
		d.Set("versionless_secret_id", secretId.VersionlessID())
	}

	certificateData := ""
	if contents := r.Cer; contents != nil {
		certificateData = strings.ToUpper(hex.EncodeToString(*contents))
	}
	d.Set("certificate_data", certificateData)

	certificateDataBase64 := ""
	if contents := r.Cer; contents != nil {
		certificateDataBase64 = base64.StdEncoding.EncodeToString(*contents)
	}
	d.Set("certificate_data_base64", certificateDataBase64)

	thumbprint := ""
	if v := r.X509Thumbprint; v != nil {
		x509Thumbprint, err := base64.RawURLEncoding.DecodeString(*v)
		if err != nil {
			diags = append(diags, diag.Errorf("unable to decode certificate thumbprint: %v", err)...)
			return diags
		}

		thumbprint = strings.ToUpper(hex.EncodeToString(x509Thumbprint))
	}
	d.Set("thumbprint", thumbprint)

	return tags.FlattenAndSet(d, r.Tags)
}

func resourceCertificateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(keyvault.BaseClient)

	parsedFromState, err := parse.ParseNestedItemID(d.Id())
	if err != nil {
		diags = append(diags, diag.Errorf("unable to parse Key Vault ID: %v", err)...)
		return diags
	}

	params := keyvault.CertificateUpdateParameters{}
	if tagsVal, ok := d.GetOk("tags"); ok {
		params.Tags = tags.Expand(tagsVal.(map[string]interface{}))
	}

	if _, err = client.UpdateCertificate(ctx, parsedFromState.KeyVaultBaseUrl, parsedFromState.Name, parsedFromState.Version, params); err != nil {
		diags = append(diags, diag.Errorf("unable to update certificate: %v", err)...)
		return diags
	}

	return resourceCertificateRead(ctx, d, meta)
}

func resourceCertificateDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
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

	_, err = client.DeleteCertificate(ctx, parsedFromState.KeyVaultBaseUrl, parsedFromState.Name)
	if err != nil {
		diags = append(diags, diag.Errorf("unable to delete Key Vault secret: %v", err)...)
		return diags
	}

	shouldPurge := d.Get("purge_on_destroy").(bool)
	if shouldPurge {
		stateChangeConf := &resource.StateChangeConf{
			Pending:                   []string{"CertificateFound"},
			Target:                    []string{"CertificateNotFound"},
			ContinuousTargetOccurence: 3,
			PollInterval:              5 * time.Second,
			Timeout:                   time.Until(timeout),
			Refresh:                   resourceCertificateDeleteRefresh(ctx, d, client),
		}

		if _, err := stateChangeConf.WaitForStateContext(ctx); err != nil {
			diags = append(diags, diag.Errorf("failed while waiting for certificate deletion: %v", err)...)
			return diags
		}

		_, err := client.PurgeDeletedCertificate(ctx, parsedFromState.KeyVaultBaseUrl, parsedFromState.Name)
		if err != nil {
			diags = append(diags, diag.Errorf("unable to purge Key Vault certificate: %v", err)...)
			return diags
		}
	}

	return nil
}

func resourceCertificateDeleteRefresh(ctx context.Context, d *schema.ResourceData, client keyvault.BaseClient) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		parsedFromState, err := parse.ParseNestedItemID(d.Id())
		if err != nil {
			return nil, "ParsingError", err
		}

		r, err := client.GetCertificate(ctx, parsedFromState.KeyVaultBaseUrl, parsedFromState.Name, "")
		if err != nil {
			tflog.Debug(ctx, fmt.Sprintf("Waiting for certificate deletion, current error is: %v", err.Error()))
			if strings.Contains(err.Error(), "CertificateNotFound") {
				tflog.Debug(ctx, "Waiting for secret deletion completed.")
				return r, "CertificateNotFound", nil
			}
		}

		return nil, "CertificateNotFound", nil
	}
}

func keyVaultCertificateCreationRefreshFunc(ctx context.Context, client *keyvault.BaseClient, keyVaultBaseUrl string, name string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		res, err := client.GetCertificate(ctx, keyVaultBaseUrl, name, "")
		if err != nil {
			return nil, "", fmt.Errorf("issuing read request in keyVaultCertificateCreationRefreshFunc for Certificate %q in Vault %q: %s", name, keyVaultBaseUrl, err)
		}

		if res.Policy != nil &&
			res.Policy.IssuerParameters != nil &&
			res.Policy.IssuerParameters.Name != nil &&
			strings.EqualFold(*(res.Policy.IssuerParameters.Name), "unknown") {
			return res, "Ready", nil
		}

		if res.Sid == nil || *res.Sid == "" {
			return nil, "Provisioning", nil
		}

		return res, "Ready", nil
	}
}

type KeyVaultCertificateImportParameters struct {
	CertificateData     string
	CertificatePassword string
}

func expandKeyVaultCertificate(v interface{}) KeyVaultCertificateImportParameters {
	certs := v.([]interface{})
	cert := certs[0].(map[string]interface{})

	return KeyVaultCertificateImportParameters{
		CertificateData:     cert["contents"].(string),
		CertificatePassword: cert["password"].(string),
	}
}

func expandKeyVaultCertificatePolicy(d *schema.ResourceData) (*keyvault.CertificatePolicy, error) {
	policies := d.Get("certificate_policy").([]interface{})
	if len(policies) == 0 || policies[0] == nil {
		return nil, nil
	}

	policyRaw := policies[0].(map[string]interface{})
	policy := keyvault.CertificatePolicy{}

	issuers := policyRaw["issuer_parameters"].([]interface{})
	issuer := issuers[0].(map[string]interface{})
	policy.IssuerParameters = &keyvault.IssuerParameters{
		Name: utils.String(issuer["name"].(string)),
	}

	properties := policyRaw["key_properties"].([]interface{})
	props := properties[0].(map[string]interface{})

	curve := props["curve"].(string)
	keyType := props["key_type"].(string)
	keySize := props["key_size"].(int)

	if keyType == string(keyvault.EC) || keyType == string(keyvault.ECHSM) {
		if curve == "" {
			return nil, fmt.Errorf("`curve` is required when creating an EC key")
		}
		// determine key_size if not specified
		if keySize == 0 {
			switch curve {
			case string(keyvault.P256), string(keyvault.P256K):
				keySize = 256
			case string(keyvault.P384):
				keySize = 384
			case string(keyvault.P521):
				keySize = 521
			}
		}
	} else if keyType == string(keyvault.RSA) || keyType == string(keyvault.RSAHSM) {
		if keySize == 0 {
			return nil, fmt.Errorf("`key_size` is required when creating an RSA key")
		}
	}

	policy.KeyProperties = &keyvault.KeyProperties{
		Curve:      keyvault.JSONWebKeyCurveName(curve),
		Exportable: utils.Bool(props["exportable"].(bool)),
		KeySize:    utils.Int32(int32(keySize)),
		KeyType:    keyvault.JSONWebKeyType(keyType),
		ReuseKey:   utils.Bool(props["reuse_key"].(bool)),
	}

	lifetimeActions := make([]keyvault.LifetimeAction, 0)
	actions := policyRaw["lifetime_action"].([]interface{})
	for _, v := range actions {
		action := v.(map[string]interface{})
		lifetimeAction := keyvault.LifetimeAction{}

		if v, ok := action["action"]; ok {
			as := v.([]interface{})
			a := as[0].(map[string]interface{})
			lifetimeAction.Action = &keyvault.Action{
				ActionType: keyvault.ActionType(a["action_type"].(string)),
			}
		}

		if v, ok := action["trigger"]; ok {
			triggers := v.([]interface{})
			if triggers[0] != nil {
				trigger := triggers[0].(map[string]interface{})
				lifetimeAction.Trigger = &keyvault.Trigger{}

				d := trigger["days_before_expiry"].(int)
				if d > 0 {
					lifetimeAction.Trigger.DaysBeforeExpiry = utils.Int32(int32(d))
				}

				p := trigger["lifetime_percentage"].(int)
				if p > 0 {
					lifetimeAction.Trigger.LifetimePercentage = utils.Int32(int32(p))
				}
			}
		}

		lifetimeActions = append(lifetimeActions, lifetimeAction)
	}
	policy.LifetimeActions = &lifetimeActions

	secrets := policyRaw["secret_properties"].([]interface{})
	secret := secrets[0].(map[string]interface{})
	policy.SecretProperties = &keyvault.SecretProperties{
		ContentType: utils.String(secret["content_type"].(string)),
	}

	certificateProperties := policyRaw["x509_certificate_properties"].([]interface{})
	for _, v := range certificateProperties {
		cert := v.(map[string]interface{})

		ekus := cert["extended_key_usage"].([]interface{})
		extendedKeyUsage := utils.ExpandStringSlice(ekus)

		keyUsage := make([]keyvault.KeyUsageType, 0)
		keys := cert["key_usage"].(*schema.Set).List()
		for _, key := range keys {
			keyUsage = append(keyUsage, keyvault.KeyUsageType(key.(string)))
		}

		subjectAlternativeNames := &keyvault.SubjectAlternativeNames{}
		if v, ok := cert["subject_alternative_names"]; ok {
			if sans := v.([]interface{}); len(sans) > 0 {
				if sans[0] != nil {
					san := sans[0].(map[string]interface{})

					emails := san["emails"].(*schema.Set).List()
					if len(emails) > 0 {
						subjectAlternativeNames.Emails = utils.ExpandStringSlice(emails)
					}

					dnsNames := san["dns_names"].(*schema.Set).List()
					if len(dnsNames) > 0 {
						subjectAlternativeNames.DNSNames = utils.ExpandStringSlice(dnsNames)
					}

					upns := san["upns"].(*schema.Set).List()
					if len(upns) > 0 {
						subjectAlternativeNames.Upns = utils.ExpandStringSlice(upns)
					}
				}
			}
		}

		policy.X509CertificateProperties = &keyvault.X509CertificateProperties{
			ValidityInMonths:        utils.Int32(int32(cert["validity_in_months"].(int))),
			Subject:                 utils.String(cert["subject"].(string)),
			KeyUsage:                &keyUsage,
			Ekus:                    extendedKeyUsage,
			SubjectAlternativeNames: subjectAlternativeNames,
		}
	}

	return &policy, nil
}

func flattenKeyVaultCertificatePolicy(input *keyvault.CertificatePolicy, certData *[]byte) []interface{} {
	if input == nil {
		return []interface{}{}
	}

	policy := make(map[string]interface{})

	if params := input.IssuerParameters; params != nil {
		issuerParams := make(map[string]interface{})
		issuerParams["name"] = *params.Name
		policy["issuer_parameters"] = []interface{}{issuerParams}
	}

	// key properties
	if props := input.KeyProperties; props != nil {
		keyProps := make(map[string]interface{})
		keyProps["curve"] = string(props.Curve)
		keyProps["exportable"] = *props.Exportable
		keyProps["key_size"] = int(*props.KeySize)
		keyProps["key_type"] = string(props.KeyType)
		keyProps["reuse_key"] = *props.ReuseKey

		policy["key_properties"] = []interface{}{keyProps}
	}

	// lifetime actions
	lifetimeActions := make([]interface{}, 0)
	if actions := input.LifetimeActions; actions != nil {
		for _, action := range *actions {
			lifetimeAction := make(map[string]interface{})

			actionOutput := make(map[string]interface{})
			if act := action.Action; act != nil {
				actionOutput["action_type"] = string(act.ActionType)
			}
			lifetimeAction["action"] = []interface{}{actionOutput}

			triggerOutput := make(map[string]interface{})
			if trigger := action.Trigger; trigger != nil {
				if days := trigger.DaysBeforeExpiry; days != nil {
					triggerOutput["days_before_expiry"] = int(*trigger.DaysBeforeExpiry)
				}

				if days := trigger.LifetimePercentage; days != nil {
					triggerOutput["lifetime_percentage"] = int(*trigger.LifetimePercentage)
				}
			}
			lifetimeAction["trigger"] = []interface{}{triggerOutput}
			lifetimeActions = append(lifetimeActions, lifetimeAction)
		}
	}
	policy["lifetime_action"] = lifetimeActions

	// secret properties
	if props := input.SecretProperties; props != nil {
		keyProps := make(map[string]interface{})
		keyProps["content_type"] = *props.ContentType

		policy["secret_properties"] = []interface{}{keyProps}
	}

	// x509 Certificate Properties
	if props := input.X509CertificateProperties; props != nil {
		certProps := make(map[string]interface{})

		usages := make([]string, 0)
		for _, usage := range *props.KeyUsage {
			usages = append(usages, string(usage))
		}

		sanOutputs := make([]interface{}, 0)
		if san := props.SubjectAlternativeNames; san != nil {
			sanOutput := make(map[string]interface{})
			if emails := san.Emails; emails != nil {
				sanOutput["emails"] = set.FromStringSlice(*emails)
			}
			if dnsNames := san.DNSNames; dnsNames != nil {
				sanOutput["dns_names"] = set.FromStringSlice(*dnsNames)
			}
			if upns := san.Upns; upns != nil {
				sanOutput["upns"] = set.FromStringSlice(*upns)
			}

			sanOutputs = append(sanOutputs, sanOutput)
		} else if certData != nil && len(*certData) > 0 {
			sanOutput := make(map[string]interface{})
			cert, err := x509.ParseCertificate(*certData)
			if err != nil {
				log.Printf("[DEBUG] Unable to read certificate data: %v", err)
			} else {
				sanOutput["emails"] = set.FromStringSlice(cert.EmailAddresses)
				sanOutput["dns_names"] = set.FromStringSlice(cert.DNSNames)
				sanOutput["upns"] = set.FromStringSlice([]string{})
				sanOutputs = append(sanOutputs, sanOutput)
			}
		}

		certProps["key_usage"] = usages
		certProps["subject"] = ""
		if props.Subject != nil {
			certProps["subject"] = *props.Subject
		}
		certProps["validity_in_months"] = int(*props.ValidityInMonths)
		if props.Ekus != nil {
			certProps["extended_key_usage"] = props.Ekus
		}
		certProps["subject_alternative_names"] = sanOutputs
		policy["x509_certificate_properties"] = []interface{}{certProps}
	}

	return []interface{}{policy}
}

func flattenKeyVaultCertificateAttribute(input *keyvault.CertificateAttributes) []interface{} {
	if input == nil {
		return []interface{}{}
	}

	enabled := false
	created := ""
	expires := ""
	notBefore := ""
	updated := ""
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	if input.Created != nil {
		created = time.Time(*input.Created).Format(time.RFC3339)
	}
	if input.Expires != nil {
		expires = time.Time(*input.Expires).Format(time.RFC3339)
	}
	if input.NotBefore != nil {
		notBefore = time.Time(*input.NotBefore).Format(time.RFC3339)
	}
	if input.Updated != nil {
		updated = time.Time(*input.Updated).Format(time.RFC3339)
	}
	return []interface{}{
		map[string]interface{}{
			"created":        created,
			"enabled":        enabled,
			"expires":        expires,
			"not_before":     notBefore,
			"recovery_level": string(input.RecoveryLevel),
			"updated":        updated,
		},
	}
}
