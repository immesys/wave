package originalstorage

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/immesys/bw2bc/crypto/sha3"
)

//const RPCPath = "/home/immesys/w/go/src/github.com/immesys/wave/chain/datadir/geth.ipc"
const RPCPath = "/home/michael/go/src/github.com/immesys/wave/client/kit/datadir/geth.ipc"

//const TestAccountAddressString = "703de98c7e4aa9b7f62046866b527697dc0c901e"
//const TestAccount = `{"address":"703de98c7e4aa9b7f62046866b527697dc0c901e","crypto":{"cipher":"aes-128-ctr","ciphertext":"b406ea947786e49a6b551abb5405db243a3a0f187b09a0f04f2633bd883e8f87","cipherparams":{"iv":"4a042b2ed82931c4e4f726bd9dacf384"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"5de958c4f2dea63093549d2a461acc121a06c08183ad541dce3b93159d8f64ea"},"mac":"cf1ca61e1bce908437dab355ee36221dc064686575de6699d289fb63d859da0e"},"id":"21d9ff46-2e2b-42fd-9c06-2dcd4e2ef772","version":3}`

var es *EthereumStorage
var storage Storage
var auth *bind.TransactOpts
var TestAccountAddress common.Address
var authmu sync.Mutex

func init() {
	var err error
	auth, err = bind.NewTransactor(strings.NewReader(TestAccount), "")
	if err != nil {
		log.Fatalf("Failed to create authorized transactor: %v", err)
	}
	es, err = NewEthereumStorage(context.Background(), RPCPath)
	if err != nil {
		panic(err)
	}
	TestAccountAddress = common.HexToAddress(TestAccountAddressString)
	storage = es
}

func TestDOT(t *testing.T) {
	t.Parallel()

	//Arbitrary data
	arbdata := make([]byte, 512)
	rand.Read(arbdata)
	arbdata2 := make([]byte, 512)
	rand.Read(arbdata2)
	dsthash := make([]byte, 32)
	rand.Read(dsthash)
	expectedHash := HashDOT(arbdata)
	expectedHash2 := HashDOT(arbdata2)

	authmu.Lock()
	trans, err := storage.InsertDOTOnChain(context.Background(), TestAccountAddress, dsthash, arbdata, auth.Signer)
	if err != nil {
		t.Fatalf("Got insert error: %v", err)
	}
	trans2, err := storage.InsertDOTOnChain(context.Background(), TestAccountAddress, dsthash, arbdata2, auth.Signer)
	if err != nil {
		t.Fatalf("Got insert error: %v", err)
	}
	authmu.Unlock()
	thash := trans.Hash()
	thash2 := trans2.Hash()
	//fmt.Printf("sleeping for DOT\n")
	time.Sleep(40 * time.Second)
	tinfo, err := storage.TransactionInfo(context.Background(), thash[:])
	if err != nil {
		t.Fatalf("Got tinfo error: %v", err)
	}
	if !tinfo.Successful {
		t.Fatalf("transaction not successful")
	}
	tinfo2, err := storage.TransactionInfo(context.Background(), thash2[:])
	if err != nil {
		t.Fatalf("Got tinfo2 error: %v", err)
	}
	if !tinfo2.Successful {
		t.Fatalf("transaction not successful")
	}
	DotEntry, si, err := storage.RetrieveDOTByEntityIndex(context.Background(), dsthash, 0)
	if err != nil {
		t.Fatalf("Got retrieve dot by vki error: %v", err)
	}
	if DotEntry == nil {
		t.Fatalf("Dot Entry is nil")
	}
	if DotEntry.Index != 0 {
		t.Fatal("Expected index 0")
	}
	if si == nil {
		t.Fatalf("si is nil")
	}
	if DotEntry.MaxIndex != 2 {
		t.Fatal("Expected a max index of 2")
	}
	if !bytes.Equal(DotEntry.Hash, expectedHash) {
		t.Fatal("Hash did not match")
	}
	if DotEntry.Location != LocationOnChain {
		t.Fatal("Expected on-chain location")
	}
	if !bytes.Equal(DotEntry.Data, arbdata) {
		t.Fatal("Data did not match")
	}
	DotEntry, si, err = storage.RetrieveDOTByEntityIndex(context.Background(), dsthash, 1)
	if err != nil {
		t.Fatalf("Got retrieve dot by vki error: %v", err)
	}
	if DotEntry == nil {
		t.Fatalf("Dot Entry is nil")
	}
	if si == nil {
		t.Fatalf("si is nil")
	}
	if DotEntry.Index != 1 {
		t.Fatal("Expected index 1")
	}
	if DotEntry.MaxIndex != 2 {
		t.Fatal("Expected a max index of 2")
	}
	if !bytes.Equal(DotEntry.Hash, expectedHash2) {
		t.Fatal("Hash did not match")
	}
	if DotEntry.Location != LocationOnChain {
		t.Fatal("Expected on-chain location")
	}
	if !bytes.Equal(DotEntry.Data, arbdata2) {
		t.Fatal("Data did not match")
	}

	// While we are here test nonexistant dot index
	DotEntry, si, err = storage.RetrieveDOTByEntityIndex(context.Background(), dsthash, 2)
	if err != nil {
		t.Fatalf("Got retrieve dot by vki error: %v", err)
	}
	if DotEntry != nil {
		t.Fatalf("Dot Entry for NE dot is not nil")
	}
	if si == nil {
		t.Fatalf("Expected non-nil si")
	}

	//Also try testing accessing dots by hash
	DotEntry, si, err = storage.RetrieveDOTByHash(context.Background(), expectedHash, LocationOnChain)
	if err != nil {
		t.Fatalf("Got retrieve dot by vki error: %v", err)
	}
	if DotEntry == nil {
		t.Fatalf("Dot Entry is nil")
	}
	if si == nil {
		t.Fatalf("si is nil")
	}
	if DotEntry.Index != -1 {
		t.Fatal("Expected index -1")
	}
	if DotEntry.MaxIndex != -1 {
		t.Fatal("Expected a max index of -1")
	}
	if !bytes.Equal(DotEntry.Hash, expectedHash) {
		t.Fatal("Hash did not match")
	}
	if DotEntry.Location != LocationOnChain {
		t.Fatal("Expected on-chain location")
	}
	if !bytes.Equal(DotEntry.Data, arbdata) {
		t.Fatal("Data did not match")
	}
}

func TestNonexistantRevocation(t *testing.T) {
	t.Parallel()
	rhash := make([]byte, 32)
	rand.Read(rhash)
	//Try retrieving revocation
	rdata, stateinfo, err := storage.RetrieveRevocation(context.Background(), rhash)
	if err != nil {
		t.Fatalf("got retrieve revocation error: %v\n")
	}
	if stateinfo == nil {
		t.Fatalf("expected non nil state info")
	}
	if rdata != nil {
		t.Fatalf("expected nil rdata rv")
	}
}
func TestRevocation(t *testing.T) {
	t.Parallel()
	lengths := []int{0, 31, 32, 300}
	for _, l := range lengths {
		t.Run(fmt.Sprintf("length_%d", l), func(t *testing.T) {
			subtestRevocationX(t, l)
		})
	}
}
func subtestRevocationX(t *testing.T, sz int) {
	t.Parallel()
	arbdata := make([]byte, sz)
	rand.Read(arbdata)
	hsh := sha3.NewKeccak256()
	hsh.Write(arbdata)
	rhash := hsh.Sum(nil)
	authmu.Lock()
	trans, err := storage.InsertRevocation(context.Background(), TestAccountAddress, arbdata, auth.Signer)
	if err != nil {
		t.Fatalf("Got insert error: %v", err)
	}
	authmu.Unlock()
	time.Sleep(40 * time.Second)
	thash := trans.Hash()
	tinfo, err := storage.TransactionInfo(context.Background(), thash[:])
	if err != nil {
		t.Fatalf("Got tinfo error: %v", err)
	}
	if !tinfo.Successful {
		t.Fatalf("Transaction did not seem to process")
	}

	//Try retrieving revocation
	rdata, stateinfo, err := storage.RetrieveRevocation(context.Background(), rhash)
	if err != nil {
		t.Fatalf("got retrieve entity error: %v\n")
	}
	if stateinfo == nil {
		t.Fatalf("expected non nil state info")
	}
	if !bytes.Equal(rdata, arbdata) {
		t.Fatalf("returned content is wrong")
	}
}
func TestEntity(t *testing.T) {
	t.Parallel()
	//Arbitrary data
	arbdata := make([]byte, 512)
	rand.Read(arbdata)
	hsh := sha3.NewKeccak256()
	hsh.Write(arbdata)
	entHash := hsh.Sum(nil)

	authmu.Lock()
	trans, err := storage.InsertEntity(context.Background(), TestAccountAddress, arbdata, auth.Signer)
	if err != nil {
		t.Fatalf("Got insert error: %v", err)
	}
	authmu.Unlock()
	time.Sleep(40 * time.Second)
	thash := trans.Hash()
	tinfo, err := storage.TransactionInfo(context.Background(), thash[:])
	if err != nil {
		t.Fatalf("Got tinfo error: %v", err)
	}
	if !tinfo.Successful {
		t.Fatalf("Transaction did not seem to process")
	}

	//Try retrieving entoty
	entityEntry, stateinfo, err := storage.RetrieveEntity(context.Background(), entHash)
	if err != nil {
		t.Fatalf("got retrieve entity error: %v\n")
	}
	if stateinfo == nil {
		t.Fatalf("expected non nil state info")
	}
	if !bytes.Equal(entityEntry.Data, arbdata) {
		t.Fatalf("returned content is wrong")
	}
}

func TestNonexistantEntity(t *testing.T) {
	t.Parallel()
	vk := make([]byte, 32)
	rand.Read(vk)
	ent, si, err := storage.RetrieveEntity(context.Background(), vk)
	if ent != nil {
		t.Fatalf("Expected nil entity rv")
	}
	if err != nil {
		t.Fatalf("Got error: %v\n", err)
	}
	if si == nil {
		t.Fatalf("Expected proper SI\n")
	}
}
func TestNonexistantDOTByHash(t *testing.T) {
	t.Parallel()
	hash := make([]byte, 32)
	rand.Read(hash)
	de, si, err := storage.RetrieveDOTByHash(context.Background(), hash, LocationOnChain)
	if de != nil {
		t.Fatalf("Expected nil de rv")
	}
	if err != nil {
		t.Fatalf("Got error: %v\n", err)
	}
	if si == nil {
		t.Fatalf("Expected proper SI\n")
	}
}
func TestNonexistantDOTByEntityIndex(t *testing.T) {
	t.Parallel()
	vk := make([]byte, 32)
	rand.Read(vk)
	de, si, err := storage.RetrieveDOTByEntityIndex(context.Background(), vk, 1)
	if de != nil {
		t.Fatalf("Expected nil de rv")
	}
	if err != nil {
		t.Fatalf("Got error: %v\n", err)
	}
	if si == nil {
		t.Fatalf("Expected proper SI\n")
	}
}

func TestAliases(t *testing.T) {
	t.Parallel()
	lengths := []int{0, 5, 31, 32, 300}
	for _, l := range lengths {
		t.Run(fmt.Sprintf("length_%d", l), func(t *testing.T) {
			subtestAliasesX(t, l)
		})
	}
}
func subtestAliasesX(t *testing.T, length int) {
	t.Parallel()
	tld := make([]byte, 32)
	rand.Read(tld)
	authmu.Lock()
	tldtrans, err := storage.CreateTLD(context.Background(), TestAccountAddress, common.BytesToHash(tld), auth.Signer)
	authmu.Unlock()
	if err != nil {
		t.Fatalf("CreateTLD error: %v", err)
	}
	time.Sleep(40 * time.Second)
	thash := tldtrans.Hash()
	tinfo, err := storage.TransactionInfo(context.Background(), thash[:])
	if err != nil {
		t.Fatalf("Got tinfo error: %v", err)
	}
	if !tinfo.Successful {
		t.Fatalf("Transaction did not seem to process: pending is %v", tinfo.Pending)
	}
	domain := make([]byte, 32)
	subdomain := make([]byte, 32)
	rand.Read(domain)
	rand.Read(subdomain)
	value := make([]byte, length)
	rand.Read(value)
	//fmt.Printf("tld: %x\ndomain: %x\nsubdomain: %x\nvalue: %x\n", tld, domain, subdomain, value)
	authmu.Lock()
	catrans, err := storage.CreateAlias(context.Background(), TestAccountAddress, common.BytesToHash(subdomain), common.BytesToHash(domain), common.BytesToHash(tld), value, auth.Signer)
	authmu.Unlock()
	if err != nil {
		t.Fatalf("Got create alias error: %v", err)
	}
	catranshash := catrans.Hash()
	time.Sleep(40 * time.Second)
	tinfo, err = storage.TransactionInfo(context.Background(), catranshash[:])
	if err != nil {
		t.Fatalf("Got tinfo error: %v", err)
	}
	if !tinfo.Successful {
		t.Fatalf("Transaction did not seem to process, pending is %v", tinfo.Pending)
	}
	aliase, si, err := storage.ResolveAlias(context.Background(), common.BytesToHash(subdomain), common.BytesToHash(domain), common.BytesToHash(tld))
	if err != nil {
		t.Fatalf("Got tinfo error: %v", err)
	}
	if si == nil {
		t.Fatalf("Expected non nil si", err)
	}
	if !bytes.Equal(aliase.Domain[:], domain) {
		t.Fatalf("rv mismatch")
	}
	if !bytes.Equal(aliase.Subdomain[:], subdomain) {
		t.Fatalf("rv mismatch")
	}
	if !bytes.Equal(aliase.TLD[:], tld) {
		t.Fatalf("rv mismatch")
	}
	if !bytes.Equal(aliase.Value, value) {
		t.Fatalf("value mismatch got (%d)%x expected (%d)%x", len(aliase.Value), aliase.Value, len(value), value)
	}

	//Lets also try resolving it as a partial alias
	aliase, si, err = storage.ResolvePartialAlias(context.Background(), common.BytesToHash(domain), common.BytesToHash(tld))
	if err != nil {
		t.Fatalf("Got tinfo error: %v", err)
	}
	if si == nil {
		t.Fatalf("Expected non nil si", err)
	}
	if !bytes.Equal(aliase.Domain[:], domain) {
		t.Fatalf("rv mismatch")
	}
	if !bytes.Equal(aliase.Subdomain[:], subdomain) {
		t.Fatalf("rv mismatch")
	}
	if !bytes.Equal(aliase.TLD[:], tld) {
		t.Fatalf("rv mismatch")
	}
	if !bytes.Equal(aliase.Value, value) {
		t.Fatalf("value mismatch got (%d)%x expected (%d)%x", len(aliase.Value), aliase.Value, len(value), value)
	}
}

func TestAliasHead(t *testing.T) {
	t.Parallel()
	tld := make([]byte, 32)
	rand.Read(tld)
	authmu.Lock()
	tldtrans, err := storage.CreateTLD(context.Background(), TestAccountAddress, common.BytesToHash(tld), auth.Signer)
	authmu.Unlock()
	if err != nil {
		t.Fatalf("CreateTLD error: %v", err)
	}
	time.Sleep(40 * time.Second)
	thash := tldtrans.Hash()
	tinfo, err := storage.TransactionInfo(context.Background(), thash[:])
	if err != nil {
		t.Fatalf("Got tinfo error: %v", err)
	}
	if !tinfo.Successful {
		t.Fatalf("Transaction did not seem to process: pending is %v", tinfo.Pending)
	}
	domain := make([]byte, 32)
	subdomain1 := make([]byte, 32)
	subdomain2 := make([]byte, 32)
	rand.Read(domain)
	rand.Read(subdomain1)
	rand.Read(subdomain2)
	value1 := make([]byte, 8)
	value2 := make([]byte, 8)
	rand.Read(value1)
	rand.Read(value2)
	//fmt.Printf("tld: %x\ndomain: %x\nsubdomain: %x\nvalue: %x\n", tld, domain, subdomain, value)
	authmu.Lock()
	catrans, err := storage.CreateAlias(context.Background(), TestAccountAddress, common.BytesToHash(subdomain1), common.BytesToHash(domain), common.BytesToHash(tld), value1, auth.Signer)
	catrans2, err := storage.CreateAlias(context.Background(), TestAccountAddress, common.BytesToHash(subdomain2), common.BytesToHash(domain), common.BytesToHash(tld), value2, auth.Signer)
	authmu.Unlock()
	if err != nil {
		t.Fatalf("Got create alias error: %v", err)
	}
	catranshash := catrans.Hash()
	catranshash2 := catrans2.Hash()
	time.Sleep(40 * time.Second)
	tinfo, err = storage.TransactionInfo(context.Background(), catranshash[:])
	if err != nil {
		t.Fatalf("Got tinfo error: %v", err)
	}
	if !tinfo.Successful {
		t.Fatalf("Transaction did not seem to process, pending is %v", tinfo.Pending)
	}
	tinfo, err = storage.TransactionInfo(context.Background(), catranshash2[:])
	if err != nil {
		t.Fatalf("Got tinfo error: %v", err)
	}
	if !tinfo.Successful {
		t.Fatalf("Transaction did not seem to process, pending is %v", tinfo.Pending)
	}
	aliase, si, err := storage.ResolveAlias(context.Background(), common.BytesToHash(subdomain1), common.BytesToHash(domain), common.BytesToHash(tld))
	if err != nil {
		t.Fatalf("Got tinfo error: %v", err)
	}
	if si == nil {
		t.Fatalf("Expected non nil si", err)
	}
	if !bytes.Equal(aliase.Domain[:], domain) {
		t.Fatalf("rv mismatch")
	}
	if !bytes.Equal(aliase.Subdomain[:], subdomain1) {
		t.Fatalf("rv mismatch")
	}
	if !bytes.Equal(aliase.TLD[:], tld) {
		t.Fatalf("rv mismatch")
	}
	if !bytes.Equal(aliase.Value, value1) {
		t.Fatalf("value mismatch got (%d)%x expected (%d)%x", len(aliase.Value), aliase.Value, len(value1), value1)
	}
	aliase, si, err = storage.ResolveAlias(context.Background(), common.BytesToHash(subdomain2), common.BytesToHash(domain), common.BytesToHash(tld))
	if err != nil {
		t.Fatalf("Got tinfo error: %v", err)
	}
	if si == nil {
		t.Fatalf("Expected non nil si", err)
	}
	if !bytes.Equal(aliase.Domain[:], domain) {
		t.Fatalf("rv mismatch")
	}
	if !bytes.Equal(aliase.Subdomain[:], subdomain2) {
		t.Fatalf("rv mismatch")
	}
	if !bytes.Equal(aliase.TLD[:], tld) {
		t.Fatalf("rv mismatch")
	}
	if !bytes.Equal(aliase.Value, value2) {
		t.Fatalf("value mismatch got (%d)%x expected (%d)%x", len(aliase.Value), aliase.Value, len(value2), value2)
	}

	//Lets also try resolving it as a partial alias
	aliase, si, err = storage.ResolvePartialAlias(context.Background(), common.BytesToHash(domain), common.BytesToHash(tld))
	if err != nil {
		t.Fatalf("Got tinfo error: %v", err)
	}
	if si == nil {
		t.Fatalf("Expected non nil si", err)
	}
	if !bytes.Equal(aliase.Domain[:], domain) {
		t.Fatalf("rv mismatch")
	}
	if !bytes.Equal(aliase.Subdomain[:], subdomain2) {
		t.Fatalf("rv mismatch")
	}
	if !bytes.Equal(aliase.TLD[:], tld) {
		t.Fatalf("rv mismatch")
	}
	if !bytes.Equal(aliase.Value, value2) {
		t.Fatalf("value mismatch got (%d)%x expected (%d)%x", len(aliase.Value), aliase.Value, len(value2), value2)
	}
}

// ResolvePartialAlias(ctx context.Context, domain [32]byte, tld [32]byte) (*AliasRegistration, *StateInformation, error)
// ResolveAlias(ctx context.Context, subdomain [32]byte, domain [32]byte, tld [32]byte) (*AliasRegistration, *StateInformation, error)
