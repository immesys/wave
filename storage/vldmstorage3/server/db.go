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
}

var DB *db

func InitDB(connstring string) error {
	// h, err := sql.Open("mysql", "user:password@/dbname")
	// if err != nil {
	// 	return err
	// }
	DB = &db{
		//	db:           h,
		mockSigRoots: make(map[string]*dbSMR),
	}
	return nil
}

func init() {
	InitDB("")
}

func (d *db) InsertSignedMapRoot(revision uint64, identity string, ts int64, r *big.Int, s *big.Int) error {
	d.mockSigRoots[identity] = &dbSMR{
		Revision:    revision,
		Timestamp:   ts,
		SigIdentity: identity,
		R:           r,
		S:           s,
	}
	return nil
}

type dbSMR struct {
	Revision    uint64
	SigIdentity string
	Timestamp   int64
	R           *big.Int
	S           *big.Int
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
