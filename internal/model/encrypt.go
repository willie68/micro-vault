package model

import "time"

// EncryptKey the key struct for transport a key
type EncryptKey struct {
	ID      string
	Alg     string
	Key     string
	Created time.Time
	Group   string
}
