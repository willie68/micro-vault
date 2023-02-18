package model

// Client the model for a client
type Client struct {
	AccessKey string
	Secret    string
	Groups    []string
}
