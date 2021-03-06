---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "azurekeyvault_secret Data Source - terraform-provider-azurekeyvault"
subcategory: ""
description: |-
  Use this data source to access information about an existing Key Vault Secret.
---

# azurekeyvault_secret (Data Source)

Use this data source to access information about an existing Key Vault Secret.

## Example Usage

```terraform
data "azurekeyvault_secret" "this" {
  key_vault_name = "MY-KV"
  name           = "MY-SECRET"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `key_vault_name` (String) The name of the target Key Vault.
- `name` (String) Specifies the name of the Key Vault Secret.

### Optional

- `id` (String) The ID of this resource.

### Read-Only

- `content_type` (String) Specifies the content type for the Key Vault Secret.
- `not_after` (String) Secret not usable after the provided UTC datetime `(Y-m-d'T'H:M:S'Z')`
- `not_before` (String) Secret not usable before the provided UTC datetime `(Y-m-d'T'H:M:S'Z')`
- `tags` (Map of String)
- `value` (String, Sensitive) Specifies the value of the Key Vault Secret.
- `version` (String) The current version of the Key Vault Secret.
- `versionless_id` (String) The Base ID of the Key Vault Secret.


