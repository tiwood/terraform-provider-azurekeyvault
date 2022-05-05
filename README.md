# Terraform Provider Azure Key Vault (`azurekeyvault`)

This provider is mostly a direct copy of the `Azure Key Vault` related resources
from the official `azurerm` provider. The main difference is, you dont have to
specify a `subscription_id` during provider initialization, which enables you
to create Key Vault resources in multiple Key Vaults, spanning `n` Azure subscriptions.

## Requirements

-	[Terraform](https://www.terraform.io/downloads.html) >= 1.x
-	[Go](https://golang.org/doc/install) >= 1.16

## Building The Provider

1. Clone the repository
2. Enter the repository directory
3. Build the provider using the Go `install` command:
  
```sh
go install
```

## Adding Dependencies

This provider uses [Go modules](https://github.com/golang/go/wiki/Modules).
Please see the Go documentation for the most up to date information about using Go modules.

To add a new dependency `github.com/author/dependency` to your Terraform provider:

```sh
go get github.com/author/dependency
go mod tidy
```

Then commit the changes to `go.mod` and `go.sum`.

## Documentation

Please refer to the
[Terraform provider registry](https://registry.terraform.io/providers/tiwood/azurekeyvault/latest/docs) for the documentation.

## Developing the Provider

If you wish to work on the provider, you'll first need [Go](http://www.golang.org) installed on your machine (see [Requirements](#requirements) above).

To compile the provider, run `go install`. This will build the provider and put the provider binary in the `$GOPATH/bin` directory.

To generate or update documentation, run `go generate`.

In order to run the full suite of Acceptance tests, run `make testacc`.

*Note:* Acceptance tests create real resources, and often cost money to run.

```sh
make testacc
```
