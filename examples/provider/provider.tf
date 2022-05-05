# Specifying required arguments in-file or as variables.
provider "azurekeyvault" {
  tenant_id     = "00000000-0000-0000-0000-000000000001"
  client_id     = "00000000-0000-0000-0000-000000000002"
  client_secret = var.YOUR_SECRET
}

# Using environment variables
provider "azurekeyvault" {}
