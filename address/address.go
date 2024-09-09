// address/address.go
package address

import (
	"errors"
	"regexp"
)

// Address1 represents a validated address string.
type Address1 string

// Define a regex for Address1 validation
var addressPattern = regexp.MustCompile(`^[a-zA-Z0-9 ,.-]{1,255}$`)

// Validate checks if the Address1 meets the criteria.
func (a Address1) Validate() error {
	if len(a) > 255 {
		return errors.New("invalid Address1: length must not exceed 255 characters")
	}
	if !addressPattern.MatchString(string(a)) {
		return errors.New("invalid Address1: contains invalid characters")
	}
	return nil
}

// Additional methods (Normalize, Sanitize, etc.) can be added as needed.