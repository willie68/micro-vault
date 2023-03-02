package pmodel

type Group struct {
	Name  string            `json:"name"`
	Label map[string]string `json:"label"`
}

type Client struct {
	Name      string   `json:"name"`
	AccessKey string   `json:"accesskey"`
	Secret    string   `json:"secret"`
	Groups    []string `json:"groups"`
}
