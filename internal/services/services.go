package services

import "errors"

// Error definitions
var (
	ErrNotImplementedYet = errors.New("not implemented yet")
	ErrAlreadyExists     = errors.New("object already exists")
	ErrLoginFailed       = errors.New("login failed")
)
