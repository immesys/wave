package originalstorage

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"sync"

	"github.com/davecgh/go-spew/spew"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/crypto/sha3"
)

var extrainfoDatabase map[common.Hash]*extrainfo

const LocationOnChain = Location(1)

func init() {
	extrainfoDatabase = make(map[common.Hash]*extrainfo)
	extrainfoDatabase[common.HexToHash("5e31ddf9f93f71ee232ca25885f39fa8b669f51013c9c01db5e7a2772ef7d69f")] = &extrainfo{
		RegistryContractAddress: common.HexToAddress("0x1742f48953f7c0D14557A078f8d6c3C40D23ED93"),
		AliasContractAddress:    common.HexToAddress("0xb2a67D61FE2EC4b22C7498036095be7dd8BF126d"),
	}
}

type Location int64

type StateInformation struct {
	CurrentBlock int64
	CurrentTime  int64
}
type TransactionInfo struct {
	Successful bool
	//TODO this will require modifying ethclient. It should give the block number the transaction was found in
	BlockNumber int64
	Pending     bool
}
type extrainfo struct {
	RegistryContractAddress common.Address
	AliasContractAddress    common.Address
}
type Storage interface {
	GetStateInformation(ctx context.Context) (*StateInformation, error)
	RetrieveEntity(ctx context.Context, Hash []byte) (*EntityRegistration, *StateInformation, error)
	RetrieveDOTByEntityIndex(ctx context.Context, DstHash []byte, index int) (*DOTRegistration, *StateInformation, error)
	RetrieveDOTByHash(ctx context.Context, hash []byte, location Location) (*DOTRegistration, *StateInformation, error)
	RetrieveRevocation(ctx context.Context, hash []byte) ([]byte, *StateInformation, error)
	ResolvePartialAlias(ctx context.Context, domain [32]byte, tld [32]byte) (*AliasRegistration, *StateInformation, error)
	ResolveAlias(ctx context.Context, subdomain [32]byte, domain [32]byte, tld [32]byte) (*AliasRegistration, *StateInformation, error)
	InsertEntity(ctx context.Context, controller common.Address, data []byte, signFn SignerFn) (*Transaction, error)
	InsertDOTOnChain(ctx context.Context, account common.Address, DstHash []byte, data []byte, signFn SignerFn) (*Transaction, error)
	InsertDOTOffChain(ctx context.Context, account common.Address, DstHash []byte, hash []byte, location uint64, signFn SignerFn) (*Transaction, error)
	InsertRevocation(ctx context.Context, account common.Address, body []byte, signFn SignerFn) (*Transaction, error)
	CreateAlias(ctx context.Context, controller common.Address, subdomain [32]byte, domain [32]byte, tld [32]byte, value []byte, signFn SignerFn) (*Transaction, error)
	CreateTLD(ctx context.Context, controller common.Address, tld [32]byte, signFn SignerFn) (*Transaction, error)
	SubscribeStorageChange(ctx context.Context, ch chan *ChangeEvent) error
	TransactionInfo(ctx context.Context, hash []byte) (*TransactionInfo, error)
}

//One weird thing to note, you should pass the SAME slice to each invocation
//of this call, as it uses the pointer address to find cached stuff
// type ChangeEvent interface {
// 	SearchForDOTGrants(dstEntHashes [][]byte) (maybe [][]byte)
// 	SearchForDOTRevocations(revHashes [][]byte) (maybe [][]byte)
// 	SearchForEntityRevocations(entHashes [][]byte) (maybe [][]byte)
// }

type ChangeEvent struct {
	//Like what sort of event it is and stuff
	IsDOT        bool
	IsRevocation bool
	IsEntity     bool

	//Entity hash, revocation hash or dot hash
	Hash []byte
	//For dots only
	DstHash []byte
}
type EthereumStorage struct {
	ctx         context.Context
	cl          *ethclient.Client
	ei          *extrainfo
	currentHead *big.Int
	currentTime *big.Int
	mu          sync.Mutex
	regTrans    *RegistryAPITransactor
	aliasTrans  *AliasAPITransactor
	subsmu      sync.Mutex
	//Using map for easy deletion and random iteration
	subs map[*headerSubscription]bool
}
type headerSubscription struct {
	client chan *ChangeEvent
	ctx    context.Context
}
type EntityRegistration struct {
	Addr common.Address
	Data []byte
}
type DOTRegistration struct {
	Hash []byte
	// Only populated if accessed via RetrieveByEntityIndex
	MaxIndex int
	Index    int
	Location Location
	// Only populated for supported locations
	Data []byte
}
type AliasRegistration struct {
	//What is the latest subdomain for this domain
	Head [32]byte
	//What subdomain is actually resolved
	Subdomain [32]byte
	Domain    [32]byte
	TLD       [32]byte
	//The value of the subdomain
	Value []byte
}

func NewEthereumStorage(ctx context.Context, ipcaddr string) (*EthereumStorage, error) {
	client, err := ethclient.Dial(ipcaddr)
	if err != nil {
		return nil, err
	}
	genesis, err := client.BlockByNumber(ctx, big.NewInt(0))
	if err != nil {
		return nil, err
	}
	extrainfo, ok := extrainfoDatabase[genesis.Hash()]
	if !ok {
		return nil, fmt.Errorf("Block chain with genesis %x is not in the database, cannot use as storage backend", genesis.Hash())

	}
	rv := &EthereumStorage{
		ctx: ctx,
		cl:  client,
		ei:  extrainfo,
	}
	rv.currentHead = big.NewInt(0)
	block, err := client.BlockByNumber(ctx, nil)
	if err != nil {
		return nil, err
	}
	rv.currentTime = block.Time()
	rv.currentHead = block.Number()
	rv.updateHead()
	rv.watchLogs()
	// NewRegistryAPITransactor creates a new write-only instance of RegistryAPI, bound to a specific deployed contract.
	regTrans, err := NewRegistryAPITransactor(extrainfo.RegistryContractAddress, client)
	if err != nil {
		return nil, err
	}
	rv.regTrans = regTrans

	aliasTrans, err := NewAliasAPITransactor(extrainfo.AliasContractAddress, client)
	if err != nil {
		return nil, err
	}
	rv.aliasTrans = aliasTrans
	return rv, nil
}
func (es *EthereumStorage) SubscribeStorageChange(ctx context.Context, ch chan *ChangeEvent) error {
	es.subsmu.Lock()
	es.subs[&headerSubscription{
		ctx:    ctx,
		client: ch,
	}] = true
	es.subsmu.Unlock()
	return nil
}
func (es *EthereumStorage) updateHead() error {
	rch := make(chan *types.Header)
	_, err := es.cl.SubscribeNewHead(context.Background(), rch)
	if err != nil {
		return err
	}
	go func() {
		for h := range rch {
			es.mu.Lock()
			es.currentHead = h.Number
			es.currentTime = h.Time
			es.mu.Unlock()
		}
		panic("current head subscription ended")
	}()
	return nil
}

func (es *EthereumStorage) watchLogs() error {
	qry := ethereum.FilterQuery{
		Addresses: []common.Address{es.ei.RegistryContractAddress},
	}
	rvch := make(chan types.Log, 100)
	sub, err := es.cl.SubscribeFilterLogs(es.ctx, qry, rvch)
	go func() {
		err := <-sub.Err()
		panic(err)
	}()
	if err != nil {
		return err
	}
	go func() {
		for l := range rvch {
			spew.Dump(l)
		}
	}()
	return nil
}

func (es *EthereumStorage) processSubscribers(s *ChangeEvent) {
	es.subsmu.Lock()
	for sub, _ := range es.subs {
		if sub.ctx.Err() != nil {
			delete(es.subs, sub)
		}
		select {
		//TODO when we do caching, make the header adapter
		//refer to a persistent cache
		case sub.client <- s:
		case <-sub.ctx.Done():
			delete(es.subs, sub)
		}
	}
	es.subsmu.Unlock()
}
func (es *EthereumStorage) getHead() (*big.Int, *big.Int) {
	es.mu.Lock()
	n := es.currentHead
	t := es.currentTime
	es.mu.Unlock()
	return n, t
}

func (es *EthereumStorage) GetStateInformation(ctx context.Context) (*StateInformation, error) {
	rv := &StateInformation{}
	n, t := es.getHead()
	if n == nil || t == nil {
		rv.CurrentBlock = 0
		rv.CurrentTime = 0
	} else {
		rv.CurrentBlock = n.Int64()
		rv.CurrentTime = t.Int64()
	}
	return rv, nil
}

func (es *EthereumStorage) RetrieveEntity(ctx context.Context, hash []byte) (*EntityRegistration, *StateInformation, error) {
	blockN, blockT := es.getHead()
	if blockN == nil || blockT == nil {
		return nil, nil, fmt.Errorf("Still synchronizing to the chain")
	}
	si := &StateInformation{
		CurrentBlock: blockN.Int64(),
		CurrentTime:  blockT.Int64(),
	}
	hsh := sha3.NewKeccak256()
	//The key to the map
	hsh.Write(hash)
	//It's the first slot
	hsh.Write(make([]byte, 32))
	sum := hsh.Sum(nil)
	addressblob, err := es.cl.StorageAt(ctx, es.ei.RegistryContractAddress, common.BytesToHash(sum), blockN)
	if err != nil {
		panic(err)
	}
	rv := EntityRegistration{}
	copy(rv.Addr[:], addressblob[12:32])
	//Nil controller implies entity does not exist
	if bytes.Equal(addressblob, make([]byte, 32)) {
		return nil, si, nil
	}
	bigval := big.NewInt(0)
	bigval.SetBytes(sum)
	bigval.Add(bigval, big.NewInt(1))
	headerAddr := common.BigToHash(bigval)
	contentsHeader, err := es.cl.StorageAt(ctx, es.ei.RegistryContractAddress, headerAddr, blockN)
	chint := bigval.SetBytes(contentsHeader)
	arrlen := chint.Int64() / 2
	slots := arrlen / 32
	hsh = sha3.NewKeccak256()
	hsh.Write(headerAddr[:])
	bigval.SetBytes(hsh.Sum(nil))
	rvbytes := []byte{}
	//include last half slot
	for i := 0; i <= int(slots); i++ {
		slotcontents, err := es.cl.StorageAt(ctx, es.ei.RegistryContractAddress, common.BigToHash(bigval), blockN)
		if err != nil {
			panic(err)
		}
		bigval.Add(bigval, big.NewInt(1))
		rvbytes = append(rvbytes, slotcontents...)
	}
	rvbytes = rvbytes[:arrlen]
	rv.Data = rvbytes

	return &rv, si, nil
}
func HashDOT(dat []byte) []byte {
	hsh := sha3.NewKeccak256()
	//The key to the map
	hsh.Write(dat)
	return hsh.Sum(nil)
}
func (es *EthereumStorage) RetrieveDOTByEntityIndex(ctx context.Context, DstHash []byte, index int) (*DOTRegistration, *StateInformation, error) {
	blockN, blockT := es.getHead()
	if blockN == nil || blockT == nil {
		return nil, nil, fmt.Errorf("Still synchronizing to the chain")
	}
	return es.retrieveDOTByEntityIndex(ctx, DstHash, index, blockN, blockT)
}

func (es *EthereumStorage) retrieveDOTByEntityIndex(ctx context.Context, DstHash []byte, index int, blockN *big.Int, blockT *big.Int) (*DOTRegistration, *StateInformation, error) {
	si := &StateInformation{
		CurrentBlock: blockN.Int64(),
		CurrentTime:  blockT.Int64(),
	}
	hsh := sha3.NewKeccak256()
	//The key to the map
	hsh.Write(DstHash)
	slot := make([]byte, 32)
	slot[31] = 1
	hsh.Write(slot)
	//The start of the array
	mainSlot := hsh.Sum(nil)
	//The length of the array
	arrayLenBytes, err := es.cl.StorageAt(ctx, es.ei.RegistryContractAddress, common.BytesToHash(mainSlot), blockN)
	if err != nil {
		panic(err)
	}
	arrayLen := new(big.Int).SetBytes(arrayLenBytes).Int64()
	if index >= int(arrayLen) {
		return nil, si, nil
	}
	rv := DOTRegistration{}
	hsh = sha3.NewKeccak256()
	hsh.Write(mainSlot)
	baseAddrHash := hsh.Sum(nil)
	const sizeOfStruct = 2
	thisEntryBase := new(big.Int).SetBytes(baseAddrHash)
	thisEntryBase.Add(thisEntryBase, big.NewInt(int64(index)*sizeOfStruct))
	entryBaseHash := common.BigToHash(thisEntryBase)
	thisEntryBase.Add(thisEntryBase, big.NewInt(1))
	entryBaseP1Hash := common.BigToHash(thisEntryBase)
	dotEntryHash, err := es.cl.StorageAt(ctx, es.ei.RegistryContractAddress, entryBaseHash, blockN)
	if err != nil {
		panic(err)
	}
	dotEntryLocation, err := es.cl.StorageAt(ctx, es.ei.RegistryContractAddress, entryBaseP1Hash, blockN)
	if err != nil {
		panic(err)
	}
	dotEntryLocationBig := new(big.Int).SetBytes(dotEntryLocation)
	rv.Data = nil
	rv.Hash = dotEntryHash
	rv.Location = Location(dotEntryLocationBig.Int64())
	rv.Index = index
	rv.MaxIndex = int(arrayLen)

	if rv.Location == LocationOnChain {
		subdr, _, err := es.retrieveDOTByHash(ctx, dotEntryHash, LocationOnChain, blockN, blockT)
		if err != nil {
			return nil, nil, err
		}
		if subdr == nil {
			//Not found
			rv.Data = nil
		} else {
			rv.Data = subdr.Data
		}
	}
	return &rv, si, nil
}

func (es *EthereumStorage) RetrieveRevocation(ctx context.Context, hash []byte) ([]byte, *StateInformation, error) {
	blockN, blockT := es.getHead()
	si := &StateInformation{
		CurrentBlock: blockN.Int64(),
		CurrentTime:  blockT.Int64(),
	}
	hsh := sha3.NewKeccak256()
	//The key to the map
	hsh.Write(hash)
	slot := make([]byte, 32)
	slot[31] = 3
	hsh.Write(slot)
	//The start of the byte array
	baseAddr := hsh.Sum(nil)
	var contents []byte
	contentsHeader, err := es.cl.StorageAt(ctx, es.ei.RegistryContractAddress, common.BytesToHash(baseAddr), blockN)
	if err != nil {
		return nil, nil, err
	}
	if contentsHeader[31]%2 == 0 {
		//Data is less than 32 bytes:
		arrlen := int(contentsHeader[31]) / 2
		contents = contentsHeader[:arrlen]
	} else {
		chint := new(big.Int).SetBytes(contentsHeader)
		arrlen := chint.Int64() / 2
		slots := arrlen / 32
		hsh = sha3.NewKeccak256()
		hsh.Write(baseAddr)
		chint.SetBytes(hsh.Sum(nil))
		rvbytes := []byte{}
		//include last half slot
		for i := 0; i <= int(slots); i++ {
			slotcontents, err := es.cl.StorageAt(ctx, es.ei.RegistryContractAddress, common.BigToHash(chint), blockN)
			if err != nil {
				panic(err)
			}
			chint.Add(chint, big.NewInt(1))
			rvbytes = append(rvbytes, slotcontents...)
		}
		contents = rvbytes[:arrlen]
	}

	hsh = sha3.NewKeccak256()
	hsh.Write(contents)
	expected := hsh.Sum(nil)
	if !bytes.Equal(expected, hash) {
		panic("somehow invalid revocation got through! tell michael")
	}
	return contents, si, nil
}

func (es *EthereumStorage) RetrieveDOTByHash(ctx context.Context, hash []byte, location Location) (*DOTRegistration, *StateInformation, error) {
	blockN, blockT := es.getHead()
	return es.retrieveDOTByHash(ctx, hash, location, blockN, blockT)
}
func (es *EthereumStorage) retrieveDOTByHash(ctx context.Context, hash []byte, location Location, blockN, blockT *big.Int) (*DOTRegistration, *StateInformation, error) {
	if location != LocationOnChain {
		panic("unsupported")
	}

	if blockN == nil || blockT == nil {
		return nil, nil, fmt.Errorf("Still synchronizing to the chain")
	}
	si := &StateInformation{
		CurrentBlock: blockN.Int64(),
		CurrentTime:  blockT.Int64(),
	}
	hsh := sha3.NewKeccak256()
	//The key to the map
	hsh.Write(hash)
	slot := make([]byte, 32)
	slot[31] = 2
	hsh.Write(slot)
	//The start of the byte array
	baseAddr := hsh.Sum(nil)

	contentsHeader, err := es.cl.StorageAt(ctx, es.ei.RegistryContractAddress, common.BytesToHash(baseAddr), blockN)
	if err != nil {
		return nil, nil, err
	}
	chint := new(big.Int).SetBytes(contentsHeader)
	arrlen := chint.Int64() / 2
	if arrlen == 0 {
		//DOT does not exist
		return nil, si, nil
	}
	slots := arrlen / 32
	hsh = sha3.NewKeccak256()
	hsh.Write(baseAddr)
	bigval := new(big.Int).SetBytes(hsh.Sum(nil))
	rvbytes := []byte{}
	//include last half slot
	for i := 0; i <= int(slots); i++ {
		slotcontents, err := es.cl.StorageAt(ctx, es.ei.RegistryContractAddress, common.BigToHash(bigval), blockN)
		if err != nil {
			panic(err)
		}
		bigval.Add(bigval, big.NewInt(1))
		rvbytes = append(rvbytes, slotcontents...)
	}
	rvbytes = rvbytes[:arrlen]

	rv := &DOTRegistration{}
	rv.Hash = make([]byte, 32)
	copy(rv.Hash, hash)
	rv.MaxIndex = -1
	rv.Index = -1
	rv.Location = LocationOnChain
	rv.Data = rvbytes
	return rv, si, nil
}

type SignerFn = bind.SignerFn
type Transaction = types.Transaction

func (es *EthereumStorage) InsertEntity(ctx context.Context, controller common.Address, data []byte, signFn SignerFn) (*Transaction, error) {
	topts := bind.TransactOpts{
		From:    controller,
		Signer:  signFn,
		Context: ctx,
	}

	tx, err := es.regTrans.RegisterEntity(&topts, data)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func (es *EthereumStorage) InsertDOTOffChain(ctx context.Context, account common.Address, DstHash []byte, hash []byte, location uint64, signFn SignerFn) (*Transaction, error) {
	topts := bind.TransactOpts{
		From:    account,
		Signer:  signFn,
		Context: ctx,
	}

	tx, err := es.regTrans.RegisterOffChainDot(&topts, common.BytesToHash(DstHash), common.BytesToHash(hash), big.NewInt(int64(location)))
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func (es *EthereumStorage) InsertDOTOnChain(ctx context.Context, account common.Address, DstHash []byte, data []byte, signFn SignerFn) (*Transaction, error) {
	topts := bind.TransactOpts{
		From:    account,
		Signer:  signFn,
		Context: ctx,
	}

	tx, err := es.regTrans.RegisterDot(&topts, common.BytesToHash(DstHash), data)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func (es *EthereumStorage) CreateAlias(ctx context.Context, account common.Address, subdomain [32]byte, domain [32]byte, tld [32]byte, value []byte, signFn SignerFn) (*Transaction, error) {
	topts := bind.TransactOpts{
		From:    account,
		Signer:  signFn,
		Context: ctx,
	}
	tx, err := es.aliasTrans.CreateSubdomain(&topts, tld, domain, subdomain, value)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func (es *EthereumStorage) CreateTLD(ctx context.Context, controller common.Address, tld [32]byte, signFn SignerFn) (*Transaction, error) {
	topts := bind.TransactOpts{
		From:    controller,
		Signer:  signFn,
		Context: ctx,
	}
	tx, err := es.aliasTrans.CreateTLD(&topts, tld)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func (es *EthereumStorage) InsertRevocation(ctx context.Context, controller common.Address, data []byte, signFn SignerFn) (*Transaction, error) {
	topts := bind.TransactOpts{
		From:    controller,
		Signer:  signFn,
		Context: ctx,
	}
	tx, err := es.regTrans.RegisterRevocation(&topts, data)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func (es *EthereumStorage) TransactionInfo(ctx context.Context, hash []byte) (*TransactionInfo, error) {
	_, pending, err := es.cl.TransactionByHash(ctx, common.BytesToHash(hash))
	if err != nil {
		return nil, err
	}
	rv := &TransactionInfo{}

	rv.Pending = pending
	if !pending {
		receipt, err := es.cl.TransactionReceipt(ctx, common.BytesToHash(hash))
		if err != nil {
			return nil, err
		}
		if receipt == nil {
			rv.Successful = false
		} else {
			rv.Successful = true
		}
	}
	return rv, nil
}

func (es *EthereumStorage) ResolvePartialAlias(ctx context.Context, domain [32]byte, tld [32]byte) (*AliasRegistration, *StateInformation, error) {
	blockN, blockT := es.getHead()
	if blockN == nil || blockT == nil {
		return nil, nil, fmt.Errorf("Still synchronizing to the chain")
	}
	//Looks up the head
	hsh := sha3.NewKeccak256()
	hsh.Write(tld[:])
	hsh.Write(make([]byte, 32))
	tldobject := hsh.Sum(nil)
	domainMap := new(big.Int).SetBytes(tldobject)
	domainMap.Add(domainMap, big.NewInt(1))
	domainMapHash := common.BigToHash(domainMap)
	hsh = sha3.NewKeccak256()
	hsh.Write(domain[:])
	hsh.Write(domainMapHash[:])
	headBytes, err := es.cl.StorageAt(ctx, es.ei.AliasContractAddress, common.BytesToHash(hsh.Sum(nil)), blockN)
	if err != nil {
		return nil, nil, err
	}
	return es.resolveAlias(ctx, common.BytesToHash(headBytes), domain, tld, blockN, blockT)
}
func (es *EthereumStorage) resolveAlias(ctx context.Context,
	subdomain [32]byte, domain [32]byte, tld [32]byte,
	blockN *big.Int, blockT *big.Int) (*AliasRegistration, *StateInformation, error) {
	si := &StateInformation{
		CurrentBlock: blockN.Int64(),
		CurrentTime:  blockT.Int64(),
	}
	hsh := sha3.NewKeccak256()
	hsh.Write(tld[:])
	hsh.Write(make([]byte, 32)) //slot 0
	tldobject := hsh.Sum(nil)
	//fmt.Printf(`test1: eth.getStorageAt("0xb2a67D61FE2EC4b22C7498036095be7dd8BF126d", "0x%x") //controller address`+"\n", tldobject)
	domainMap := new(big.Int).SetBytes(tldobject)
	domainMap.Add(domainMap, big.NewInt(1))
	hsh = sha3.NewKeccak256()
	hsh.Write(domain[:])
	domainMapHash := common.BigToHash(domainMap)
	hsh.Write(domainMapHash[:])
	domainObject := hsh.Sum(nil)
	//fmt.Printf(`test2: eth.getStorageAt("0xb2a67D61FE2EC4b22C7498036095be7dd8BF126d", "0x%x") //head subd`+"\n", domainObject)
	subdomainMap := new(big.Int).SetBytes(domainObject)
	subdomainMap.Add(subdomainMap, big.NewInt(1))
	subdomainMapHash := common.BigToHash(subdomainMap)
	hsh = sha3.NewKeccak256()
	hsh.Write(subdomain[:])
	hsh.Write(subdomainMapHash[:])
	subdomainBytesObject := hsh.Sum(nil)
	//fmt.Printf(`test2: eth.getStorageAt("0xb2a67D61FE2EC4b22C7498036095be7dd8BF126d", "0x%x") //bytes header`+"\n", subdomainBytesObject)
	headBytes, err := es.cl.StorageAt(ctx, es.ei.AliasContractAddress, common.BytesToHash(domainObject), blockN)
	if err != nil {
		return nil, nil, err
	}

	ar := AliasRegistration{
		Head: common.BytesToHash(headBytes),
		//What subdomain is actually resolved
		Subdomain: subdomain,
		Domain:    domain,
		TLD:       tld,
	}

	//TODO proper bytes depacking
	contentsHeader, err := es.cl.StorageAt(ctx, es.ei.AliasContractAddress, common.BytesToHash(subdomainBytesObject), blockN)
	if err != nil {
		return nil, nil, err
	}
	if contentsHeader[31]%2 == 0 {
		//Data is less than 32 bytes:
		arrlen := int(contentsHeader[31]) / 2
		ar.Value = contentsHeader[:arrlen]
	} else {
		chint := new(big.Int).SetBytes(contentsHeader)
		arrlen := chint.Int64() / 2
		slots := arrlen / 32
		hsh = sha3.NewKeccak256()
		hsh.Write(subdomainBytesObject)
		chint.SetBytes(hsh.Sum(nil))
		rvbytes := []byte{}
		//include last half slot
		for i := 0; i <= int(slots); i++ {
			slotcontents, err := es.cl.StorageAt(ctx, es.ei.AliasContractAddress, common.BigToHash(chint), blockN)
			if err != nil {
				panic(err)
			}
			chint.Add(chint, big.NewInt(1))
			rvbytes = append(rvbytes, slotcontents...)
		}
		ar.Value = rvbytes[:arrlen]
	}

	return &ar, si, nil
}
func (es *EthereumStorage) ResolveAlias(ctx context.Context, subdomain [32]byte, domain [32]byte, tld [32]byte) (*AliasRegistration, *StateInformation, error) {
	blockN, blockT := es.getHead()
	if blockN == nil || blockT == nil {
		return nil, nil, fmt.Errorf("Still synchronizing to the chain")
	}
	return es.resolveAlias(ctx, subdomain, domain, tld, blockN, blockT)
}
