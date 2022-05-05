package set

import (
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func HashInt(v interface{}) int {
	return schema.HashString(strconv.Itoa(v.(int)))
}

func HashStringIgnoreCase(v interface{}) int {
	return schema.HashString(strings.ToLower(v.(string)))
}

func FromStringSlice(slice []string) *schema.Set {
	set := &schema.Set{F: schema.HashString}
	for _, v := range slice {
		set.Add(v)
	}
	return set
}

func FromStringSliceNilable(slice *[]string) *schema.Set {
	if slice == nil {
		return nil
	}

	set := &schema.Set{F: schema.HashString}
	for _, v := range *slice {
		set.Add(v)
	}
	return set
}
