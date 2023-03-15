package model

// Client the model for a client
type Client struct {
	Name      string   `json:"name"`
	AccessKey string   `json:"accesskey"`
	Secret    string   `json:"secret"`
	Groups    []string `json:"groups"`
	Key       string   `json:"key"`
	KID       string   `json:"kid"`
}
