package apiv1

import (
	"fmt"
	"net/http"
	"strings"
)

// APIVersion the actual implemented api version
const APIVersion = "1"

// BaseURL is the url all endpoints will be available under
var BaseURL = fmt.Sprintf("/api/v%s", APIVersion)

// defining all sub pathes for api v1
const configSubpath = "/config"
const vaultSubpath = "/vault"
const adminSubpath = "/admin"

func token(r *http.Request) (string, error) {
	tk := r.Header.Get("Authorization")
	tk = strings.TrimPrefix(tk, "Bearer ")
	return tk, nil
}
