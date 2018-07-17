package common

type Auth interface {
	Init()
	GetPolicy(authinfo []byte) *Policy
}

type Policy struct {
	Permissions []string
	Resources   []string
}
