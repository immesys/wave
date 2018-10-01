package main

import (
	"database/sql"
	"math/big"

	_ "github.com/go-sql-driver/mysql"
)

type db struct {
	db *sql.DB

	//mock: should be a db table
	mockSigRoots map[string]*dbSMR
	mockObjects  map[string][]byte
}

var DB *db

func InitDB(connstring string) error {
	// h, err := sql.Open("mysql", connstring)
	// if err != nil {
	// 	return err
	// }
	DB = &db{
		//	db:           h,
		mockSigRoots: make(map[string]*dbSMR),
		mockObjects:  make(map[string][]byte),
	}
	return nil
}

func init() {
	InitDB("")
}

func (d *db) InsertObject(hash []byte, object []byte) error {
	d.mockObjects[string(hash)] = object
	return nil
}
func (d *db) RetrieveObject(hash []byte) ([]byte, error) {
	return d.mockObjects[string(hash)], nil
}

func (d *db) InsertSignedMapRoot(v *dbSMR) error {
	d.mockSigRoots[v.SigIdentity] = v
	return nil
}

type dbSMR struct {
	Revision    uint64
	SigIdentity string
	Timestamp   int64
	R           *big.Int
	S           *big.Int

	//Proof the SMR is in the log
	LogInclusion  []byte
	LogSignedRoot []byte
	LogSize       int64
}

func (d *db) GetLatestMapRootSignature(identities []string) (*dbSMR, error) {
	var found *dbSMR
	for _, id := range identities {
		e, ok := d.mockSigRoots[id]
		if ok && (found == nil || found.Revision < e.Revision) {
			found = e
		}
	}
	return found, nil
}
