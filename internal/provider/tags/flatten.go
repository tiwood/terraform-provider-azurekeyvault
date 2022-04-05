package tags

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func Flatten(tagMap map[string]*string) map[string]interface{} {
	// If tagsMap is nil, len(tagsMap) will be 0.
	output := make(map[string]interface{}, len(tagMap))

	for i, v := range tagMap {
		if v == nil {
			continue
		}

		output[i] = *v
	}

	return output
}

func FlattenAndSet(d *schema.ResourceData, tagMap map[string]*string) diag.Diagnostics {
	flattened := Flatten(tagMap)
	if err := d.Set("tags", flattened); err != nil {
		return diag.Errorf("settings `tags` failed: %v", err)
	}

	return nil
}
