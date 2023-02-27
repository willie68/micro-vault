package apiv1

import "fmt"

// APIVersion the actual implemented api version
const APIVersion = "1"

// BaseURL is the url all endpoints will be available under
var BaseURL = fmt.Sprintf("/api/v%s", APIVersion)

// defining all sub pathes for api v1
const configSubpath = "/config"
const vaultSubpath = "/vault"
