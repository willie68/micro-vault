package pmodel

import "time"

// Group the public group model
type Group struct {
	Name     string            `json:"name"`
	Label    map[string]string `json:"label"`
	IsClient bool              `json:"isclient"`
}

// Client the public client model
type Client struct {
	Name      string   `json:"name"`
	AccessKey string   `json:"accesskey"`
	Secret    string   `json:"secret"`
	Groups    []string `json:"groups"`
	KID       string   `json:"kid,omitempty"`
	Key       string   `json:"key,omitempty"`
}

// Message this is a message for a en/decrypting request
type Message struct {
	Type      string `json:"type"`      // The type of message means group for group messages or private for a private message
	Origin    string `json:"origin"`    // who sends this message, group name or client name
	Recipient string `json:"recipient"` // who should receive this message, group name or client name
	ID        string `json:"id"`        // only set when the AES key is already created
	Decrypt   bool   `json:"decrypt"`   // True for message decryption and false for message encryption
	Message   string `json:"message"`   // the message to en/decrypt
}

// SignMessage this is a message for a en/decrypting request
type SignMessage struct {
	KeyInfo   KeyInfo `json:"keyInfo"`
	Message   string  `json:"message"`   // the message to sign
	Signature string  `json:"signature"` // the signature
	Valid     bool    `json:"valid"`
}

// KeyInfo some information about the used key
type KeyInfo struct {
	Alg string `json:"alg"`
	KID string `json:"kid"`
}

// EncryptKeyInfo some information about the used key
type EncryptKeyInfo struct {
	Alg     string    `json:"alg"`
	ID      string    `json:"kid"`
	Group   string    `json:"group"`
	Key     string    `json:"key"`
	Created time.Time `json:"created"`
}
