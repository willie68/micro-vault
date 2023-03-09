package pmodel

// Group the public group model
type Group struct {
	Name  string            `json:"name"`
	Label map[string]string `json:"label"`
}

// Client the public client model
type Client struct {
	Name      string   `json:"name"`
	AccessKey string   `json:"accesskey"`
	Secret    string   `json:"secret"`
	Groups    []string `json:"groups"`
}

// Message this is a message for a en/decrypting request
type Message struct {
	Type      string `json:"type"`      // The type of message means group for group messages or private for a private message
	Recipient string `json:"recipient"` // who should receive this message, group name or client name
	ID        string `json:"id"`        // only set when the AES key is already created
	Decrypt   bool   `json:"decrypt"`   // True for message decryption and false for message encryption
	Message   string `json:"message"`   // the message to en/decrypt
}
