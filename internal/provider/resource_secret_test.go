package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccResourceSecret(t *testing.T) {
	t.Skip("resource not yet implemented, remove this once you add your own code")

	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceSecret,
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr(
						"azurekeyvault_secret.test", "sample_attribute", regexp.MustCompile("^ba")),
				),
			},
		},
	})
}

const testAccResourceSecret = `
resource "azurekeyvault_secret" "test" {
	key_vault_name   = ""
  name             = ""
  value            = ""
	content_type     = ""
  purge_on_destroy = true
}
`
