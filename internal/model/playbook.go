package model

// Playbook model for the playbook file
type Playbook struct {
	Groups  []Group  `json:"groups"`
	Clients []Client `json:"clients"`
}
