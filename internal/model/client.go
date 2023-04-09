package model

// Client the model for a client
type Client struct {
	Name      string   `json:"name"`
	Salt      string   `json:"salt"`
	AccessKey string   `json:"accesskey"`
	Secret    string   `json:"secret,omitempty"` // BEWARE: Only for usage in playbook
	Hash      string   `json:"hash"`
	Groups    []string `json:"groups"`
	Key       string   `json:"key"`
	KID       string   `json:"kid"`
}
