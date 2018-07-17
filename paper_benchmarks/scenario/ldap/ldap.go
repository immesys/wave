package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"strings"

	"database/sql"

	"github.com/davecgh/go-spew/spew"
	_ "github.com/go-sql-driver/mysql"
	"github.com/immesys/wave/paper_benchmarks/scenario/common"
	ldap "gopkg.in/ldap.v2"
)

var ldapconn *ldap.Conn
var mysqlconn *sql.DB

func GetPolicy(authinfo []byte) *common.Policy {
	//then := time.Now()
	userpass := string(authinfo)
	parts := strings.SplitN(userpass, ":", 2)
	user := parts[0]
	pass := parts[1]

	searchRequest := ldap.NewSearchRequest(
		"OU=People,o=eecs.berkeley.edu,dc=eecs,dc=berkeley,dc=edu",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(uid=%s)", user),
		[]string{"cn", "memberOf", "dn"},
		nil,
	)

	sr, err := ldapconn.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	if len(sr.Entries) != 1 {
		log.Fatal("User does not exist or too many entries returned")
	}

	//fmt.Printf("delta1: %s\n", time.Since(then))
	//spew.Dump(sr)
	userdn := sr.Entries[0].DN
	groups := sr.Entries[0].Attributes[1].Values

	// Bind as the user to verify their password
	err = ldapconn.Bind(userdn, pass)
	if err != nil {
		log.Fatal(err)
	}

	// Rebind as the read only user for any further queries
	err = ldapconn.Bind("", "")
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Printf("delta2: %s\n", time.Since(then))
	rv := &common.Policy{}
	_ = groups
	// for _, grp := range groups {
	// 	rows, err := mysqlconn.Query("SELECT resource,permission FROM permissions WHERE `group`=?", grp)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	rows.Next()
	// 	var res, perm string
	// 	err = rows.Scan(&res, &perm)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	rv.Permissions = append(rv.Permissions, perm)
	// 	rv.Resources = append(rv.Resources, res)
	// 	rows.Close()
	// }
	//fmt.Printf("delta3: %s\n", time.Since(then))
	return rv
}
func Init() {

	db, err := sql.Open("mysql", "ldap:ldap@/ldap")
	if err != nil {
		panic(err)
	}
	server := "ldap.eecs.berkeley.edu"

	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", server, 389))
	if err != nil {
		log.Fatal(err)
	}

	// Reconnect with TLS
	err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Fatal(err)
	}

	ldapconn = l
	mysqlconn = db
}

func main() {

	Init()
	pol := GetPolicy([]byte("m.andersen:" + os.Getenv("LDAP_PASS")))
	spew.Dump(pol)
}
