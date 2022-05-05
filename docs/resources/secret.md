---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "azurekeyvault_secret Resource - terraform-provider-azurekeyvault"
subcategory: ""
description: |-
  Manages a Key Vault Secret.
---

# azurekeyvault_secret (Resource)

Manages a Key Vault Secret.

## Example Usage

```terraform
resource "azurekeyvault_secret" "this" {
  key_vault_name   = "MYKV"
  name             = "baz"
  value            = "bar"
  purge_on_destroy = true
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `key_vault_name` (String) The name of the target Key Vault.
- `name` (String) Specifies the name of the Key Vault Secret.
- `value` (String, Sensitive) Specifies the value of the Key Vault Secret.

### Optional

- `content_type` (String) Specifies the content type for the Key Vault Secret.
- `id` (String) The ID of this resource.
- `not_after` (String) Secret not usable after the provided UTC datetime `(Y-m-d'T'H:M:S'Z')`
- `not_before` (String) Secret not usable before the provided UTC datetime `(Y-m-d'T'H:M:S'Z')`
- `purge_on_destroy` (Boolean) Whether the Certificate should be purged during destroy.
- `tags` (Map of String)

### Read-Only

- `version` (String) The current version of the Key Vault Secret.
- `versionless_id` (String) The Base ID of the Key Vault Secret.

