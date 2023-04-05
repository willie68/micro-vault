package model

// Group model for a group
type Group struct {
	Name  string            `json:"name"`
	Label map[string]string `json:"label"`
	Key   string            `json:"key"`
	KID   string            `json:"kid"`
}
