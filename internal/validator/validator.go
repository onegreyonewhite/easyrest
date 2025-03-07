package validator

import (
	"errors"
	"regexp"
)

var identifierRegexp = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var orderingRegexp = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\s+(ASC|DESC))?$`)

// ValidateIdentifier checks if the provided identifier (table or field name) is safe.
func ValidateIdentifier(id string) error {
	if !identifierRegexp.MatchString(id) {
		return errors.New("Invalid identifier: " + id)
	}
	return nil
}

// ValidateOrdering checks if the ordering clause is safe.
func ValidateOrdering(order string) error {
	if !orderingRegexp.MatchString(order) {
		return errors.New("Invalid ordering field: " + order)
	}
	return nil
}
