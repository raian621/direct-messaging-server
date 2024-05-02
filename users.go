package main

import "fmt"

type IdentifierExistsError struct {
	Identifier     string
	IdentifierType string
}

func (e *IdentifierExistsError) Error() string {
	return fmt.Sprintf("%s '%s' already exists", e.IdentifierType, e.Identifier)
}

func TryCreateUser(credentials struct {
	Username string
	Email    string
	Password string
}) error {
	return nil
}
