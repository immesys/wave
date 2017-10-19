package storage

type StateInformation struct {
	//What block we got the data from
	//Peers
}
type TransactionApprover interface {
}
type TransactionInformation struct {
}
type Storage interface {
	GetStateInformation() (StateInformation, error)
	RetrieveEntityItem(VK []byte, index int) ([]byte, *StateInformation, error)
	RetrieveDOTItem(DstVK []byte, index int) ([]byte, *StateInformation, error)
	ResolveAlias(alias string) ([]byte, *StateInformation, error)
	InsertEntityItem(VK []byte, item []byte, tap *TransactionApprover) (*TransactionInformation, error)
	InsertDOTItem(DstVK []byte, item []byte, tap *TransactionApprover) (*TransactionInformation, error)
	CreateAlias(alias string, value []byte, tap *TransactionApprover) (*TransactionInformation, error)
}
