package main

import "github.com/willie68/micro-vault/pkg/client"

const (
	AccessKey string = "12345678"
	Secret    string = "e7d767cd1432145820669be6a60a912e"
	BaseURL   string = "https://127.0.0.1:9543"
)

var cli client.Client

func main() {
	// Constructor pattern
	cli, err := client.LoginClient(AccessKey, Secret, BaseURL)
	if err != nil {
		panic(err)
	}
	cli.Logout()
	// Builder pattern
	cli, err = client.NewClient().
		WithAccessKey(AccessKey).
		WithSecret(Secret).
		WithBaseURL(BaseURL).
		Login()
	if err != nil {
		panic(err)
	}
	cli.Logout()
}

// create certificate
// create and use encryption key
// use server side encryption
// sign a text, and validate it
// secure store and retrive
