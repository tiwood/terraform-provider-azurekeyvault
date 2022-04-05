package tags

import "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

// SchemaDataSource returns the Schema which should be used for Tags on a Data Source
func SchemaDataSource() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeMap,
		Computed: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
	}
}

// Schema returns the Schema used for Tags
func Schema() *schema.Schema {
	return &schema.Schema{
		Type:         schema.TypeMap,
		Optional:     true,
		ValidateFunc: Validate,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
	}
}
