terraform {
  required_providers {
    pkcs12 = {
      source  = "chilicat/pkcs12"
      version = "0.0.7"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 3.1.0"
    }
  }
}

provider "azurekeyvault" {}

resource "tls_private_key" "this" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_self_signed_cert" "this" {
  key_algorithm         = "RSA"
  private_key_pem       = tls_private_key.this.private_key_pem
  validity_period_hours = 26298

  subject {
    common_name    = "CN=this"
    serial_number  = "000000001"
    street_address = []
  }

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "client_auth",
  ]
}

resource "pkcs12_from_pem" "this" {
  password        = "secret-sauce"
  cert_pem        = tls_self_signed_cert.this.cert_pem
  private_key_pem = tls_private_key.this.private_key_pem
}

resource "azurekeyvault_certificate" "this" {
  name             = "this"
  key_vault_name   = "MYKV"
  purge_on_destroy = true

  certificate {
    contents = pkcs12_from_pem.this.result
    password = pkcs12_from_pem.this.password
  }

  certificate_policy {
    issuer_parameters {
      name = "Self"
    }

    key_properties {
      exportable = true
      key_size   = 4096
      key_type   = "RSA"
      reuse_key  = false
    }

    secret_properties {
      content_type = "application/x-pkcs12"
    }
  }
}
