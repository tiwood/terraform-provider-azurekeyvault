data "azurekeyvault_secret" "this" {
  key_vault_name = "MY-KV"
  name           = "MY-SECRET"
}
