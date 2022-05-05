resource "azurekeyvault_secret" "this" {
  key_vault_name   = "MYKV"
  name             = "baz"
  value            = "bar"
  purge_on_destroy = true
}
