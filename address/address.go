// address/address.go
package address

import (
	"errors"
	"regexp"
)

// Address1 represents a validated address string.
type Address1 string
type PhoneNumber1 uint64

// Define a regex for Address1 validation
var addressPattern = regexp.MustCompile(`^[a-zA-Z0-9 ,.-]{1,255}$`)
var gValidatePhoneLengthPattern = regexp.MustCompile(`^\d{10}$`)

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

// Validate checks if the phoneNumber meets the criteria (10 digits).
func (p PhoneNumber1) Validate() error {
	// Check if the phone number is in the valid range for 10 digits
	if p < 1000000000 || p > 9999999999 {
		return errors.New("invalid phoneNumber: must contain exactly 10 digits")
	}
	return nil
}

// Additional methods (Normalize, Sanitize, etc.) can be added as needed.
