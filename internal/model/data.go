package model

import "time"

// Data a model for the data store
type Data struct {
	ID      string    `json:"id"`
	Expires time.Time `json:"expires"`
	Created time.Time `json:"created"`
	Group   string    `json:"group"`
	Payload string    `json:"payload"`
}
