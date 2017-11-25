// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package storage

import (
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// RegistryAPIABI is the input ABI used to generate the binding from.
const RegistryAPIABI = "[{\"constant\":false,\"inputs\":[{\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"registerRevocation\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"dotsByHash\",\"outputs\":[{\"name\":\"\",\"type\":\"bytes\",\"value\":\"0x\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"dsthash\",\"type\":\"bytes32\"},{\"name\":\"hash\",\"type\":\"bytes32\"},{\"name\":\"storageType\",\"type\":\"uint256\"}],\"name\":\"registerOffChainDot\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"dsthash\",\"type\":\"bytes32\"},{\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"registerDot\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"revocations\",\"outputs\":[{\"name\":\"\",\"type\":\"bytes\",\"value\":\"0x\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"registerEntity\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"entities\",\"outputs\":[{\"name\":\"controller\",\"type\":\"address\",\"value\":\"0x0000000000000000000000000000000000000000\"},{\"name\":\"data\",\"type\":\"bytes\",\"value\":\"0x\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\"},{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"dots\",\"outputs\":[{\"name\":\"hash\",\"type\":\"bytes32\",\"value\":\"0x\"},{\"name\":\"storageType\",\"type\":\"uint256\",\"value\":\"0\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"}]"

// RegistryAPI is an auto generated Go binding around an Ethereum contract.
type RegistryAPI struct {
	RegistryAPICaller     // Read-only binding to the contract
	RegistryAPITransactor // Write-only binding to the contract
}

// RegistryAPICaller is an auto generated read-only Go binding around an Ethereum contract.
type RegistryAPICaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RegistryAPITransactor is an auto generated write-only Go binding around an Ethereum contract.
type RegistryAPITransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RegistryAPISession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type RegistryAPISession struct {
	Contract     *RegistryAPI      // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// RegistryAPICallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type RegistryAPICallerSession struct {
	Contract *RegistryAPICaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts      // Call options to use throughout this session
}

// RegistryAPITransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type RegistryAPITransactorSession struct {
	Contract     *RegistryAPITransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts      // Transaction auth options to use throughout this session
}

// RegistryAPIRaw is an auto generated low-level Go binding around an Ethereum contract.
type RegistryAPIRaw struct {
	Contract *RegistryAPI // Generic contract binding to access the raw methods on
}

// RegistryAPICallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type RegistryAPICallerRaw struct {
	Contract *RegistryAPICaller // Generic read-only contract binding to access the raw methods on
}

// RegistryAPITransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type RegistryAPITransactorRaw struct {
	Contract *RegistryAPITransactor // Generic write-only contract binding to access the raw methods on
}

// NewRegistryAPI creates a new instance of RegistryAPI, bound to a specific deployed contract.
func NewRegistryAPI(address common.Address, backend bind.ContractBackend) (*RegistryAPI, error) {
	contract, err := bindRegistryAPI(address, backend, backend)
	if err != nil {
		return nil, err
	}
	return &RegistryAPI{RegistryAPICaller: RegistryAPICaller{contract: contract}, RegistryAPITransactor: RegistryAPITransactor{contract: contract}}, nil
}

// NewRegistryAPICaller creates a new read-only instance of RegistryAPI, bound to a specific deployed contract.
func NewRegistryAPICaller(address common.Address, caller bind.ContractCaller) (*RegistryAPICaller, error) {
	contract, err := bindRegistryAPI(address, caller, nil)
	if err != nil {
		return nil, err
	}
	return &RegistryAPICaller{contract: contract}, nil
}

// NewRegistryAPITransactor creates a new write-only instance of RegistryAPI, bound to a specific deployed contract.
func NewRegistryAPITransactor(address common.Address, transactor bind.ContractTransactor) (*RegistryAPITransactor, error) {
	contract, err := bindRegistryAPI(address, nil, transactor)
	if err != nil {
		return nil, err
	}
	return &RegistryAPITransactor{contract: contract}, nil
}

// bindRegistryAPI binds a generic wrapper to an already deployed contract.
func bindRegistryAPI(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(RegistryAPIABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_RegistryAPI *RegistryAPIRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _RegistryAPI.Contract.RegistryAPICaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_RegistryAPI *RegistryAPIRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _RegistryAPI.Contract.RegistryAPITransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_RegistryAPI *RegistryAPIRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _RegistryAPI.Contract.RegistryAPITransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_RegistryAPI *RegistryAPICallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _RegistryAPI.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_RegistryAPI *RegistryAPITransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _RegistryAPI.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_RegistryAPI *RegistryAPITransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _RegistryAPI.Contract.contract.Transact(opts, method, params...)
}

// Dots is a free data retrieval call binding the contract method 0xefb49d2d.
//
// Solidity: function dots( bytes32,  uint256) constant returns(hash bytes32, storageType uint256)
func (_RegistryAPI *RegistryAPICaller) Dots(opts *bind.CallOpts, arg0 [32]byte, arg1 *big.Int) (struct {
	Hash        [32]byte
	StorageType *big.Int
}, error) {
	ret := new(struct {
		Hash        [32]byte
		StorageType *big.Int
	})
	out := ret
	err := _RegistryAPI.contract.Call(opts, out, "dots", arg0, arg1)
	return *ret, err
}

// Dots is a free data retrieval call binding the contract method 0xefb49d2d.
//
// Solidity: function dots( bytes32,  uint256) constant returns(hash bytes32, storageType uint256)
func (_RegistryAPI *RegistryAPISession) Dots(arg0 [32]byte, arg1 *big.Int) (struct {
	Hash        [32]byte
	StorageType *big.Int
}, error) {
	return _RegistryAPI.Contract.Dots(&_RegistryAPI.CallOpts, arg0, arg1)
}

// Dots is a free data retrieval call binding the contract method 0xefb49d2d.
//
// Solidity: function dots( bytes32,  uint256) constant returns(hash bytes32, storageType uint256)
func (_RegistryAPI *RegistryAPICallerSession) Dots(arg0 [32]byte, arg1 *big.Int) (struct {
	Hash        [32]byte
	StorageType *big.Int
}, error) {
	return _RegistryAPI.Contract.Dots(&_RegistryAPI.CallOpts, arg0, arg1)
}

// DotsByHash is a free data retrieval call binding the contract method 0x24557875.
//
// Solidity: function dotsByHash( bytes32) constant returns(bytes)
func (_RegistryAPI *RegistryAPICaller) DotsByHash(opts *bind.CallOpts, arg0 [32]byte) ([]byte, error) {
	var (
		ret0 = new([]byte)
	)
	out := ret0
	err := _RegistryAPI.contract.Call(opts, out, "dotsByHash", arg0)
	return *ret0, err
}

// DotsByHash is a free data retrieval call binding the contract method 0x24557875.
//
// Solidity: function dotsByHash( bytes32) constant returns(bytes)
func (_RegistryAPI *RegistryAPISession) DotsByHash(arg0 [32]byte) ([]byte, error) {
	return _RegistryAPI.Contract.DotsByHash(&_RegistryAPI.CallOpts, arg0)
}

// DotsByHash is a free data retrieval call binding the contract method 0x24557875.
//
// Solidity: function dotsByHash( bytes32) constant returns(bytes)
func (_RegistryAPI *RegistryAPICallerSession) DotsByHash(arg0 [32]byte) ([]byte, error) {
	return _RegistryAPI.Contract.DotsByHash(&_RegistryAPI.CallOpts, arg0)
}

// Entities is a free data retrieval call binding the contract method 0xe5b338fd.
//
// Solidity: function entities( bytes32) constant returns(controller address, data bytes)
func (_RegistryAPI *RegistryAPICaller) Entities(opts *bind.CallOpts, arg0 [32]byte) (struct {
	Controller common.Address
	Data       []byte
}, error) {
	ret := new(struct {
		Controller common.Address
		Data       []byte
	})
	out := ret
	err := _RegistryAPI.contract.Call(opts, out, "entities", arg0)
	return *ret, err
}

// Entities is a free data retrieval call binding the contract method 0xe5b338fd.
//
// Solidity: function entities( bytes32) constant returns(controller address, data bytes)
func (_RegistryAPI *RegistryAPISession) Entities(arg0 [32]byte) (struct {
	Controller common.Address
	Data       []byte
}, error) {
	return _RegistryAPI.Contract.Entities(&_RegistryAPI.CallOpts, arg0)
}

// Entities is a free data retrieval call binding the contract method 0xe5b338fd.
//
// Solidity: function entities( bytes32) constant returns(controller address, data bytes)
func (_RegistryAPI *RegistryAPICallerSession) Entities(arg0 [32]byte) (struct {
	Controller common.Address
	Data       []byte
}, error) {
	return _RegistryAPI.Contract.Entities(&_RegistryAPI.CallOpts, arg0)
}

// Revocations is a free data retrieval call binding the contract method 0xbbe48780.
//
// Solidity: function revocations( bytes32) constant returns(bytes)
func (_RegistryAPI *RegistryAPICaller) Revocations(opts *bind.CallOpts, arg0 [32]byte) ([]byte, error) {
	var (
		ret0 = new([]byte)
	)
	out := ret0
	err := _RegistryAPI.contract.Call(opts, out, "revocations", arg0)
	return *ret0, err
}

// Revocations is a free data retrieval call binding the contract method 0xbbe48780.
//
// Solidity: function revocations( bytes32) constant returns(bytes)
func (_RegistryAPI *RegistryAPISession) Revocations(arg0 [32]byte) ([]byte, error) {
	return _RegistryAPI.Contract.Revocations(&_RegistryAPI.CallOpts, arg0)
}

// Revocations is a free data retrieval call binding the contract method 0xbbe48780.
//
// Solidity: function revocations( bytes32) constant returns(bytes)
func (_RegistryAPI *RegistryAPICallerSession) Revocations(arg0 [32]byte) ([]byte, error) {
	return _RegistryAPI.Contract.Revocations(&_RegistryAPI.CallOpts, arg0)
}

// RegisterDot is a paid mutator transaction binding the contract method 0x6fa36c80.
//
// Solidity: function registerDot(dsthash bytes32, data bytes) returns()
func (_RegistryAPI *RegistryAPITransactor) RegisterDot(opts *bind.TransactOpts, dsthash [32]byte, data []byte) (*types.Transaction, error) {
	return _RegistryAPI.contract.Transact(opts, "registerDot", dsthash, data)
}

// RegisterDot is a paid mutator transaction binding the contract method 0x6fa36c80.
//
// Solidity: function registerDot(dsthash bytes32, data bytes) returns()
func (_RegistryAPI *RegistryAPISession) RegisterDot(dsthash [32]byte, data []byte) (*types.Transaction, error) {
	return _RegistryAPI.Contract.RegisterDot(&_RegistryAPI.TransactOpts, dsthash, data)
}

// RegisterDot is a paid mutator transaction binding the contract method 0x6fa36c80.
//
// Solidity: function registerDot(dsthash bytes32, data bytes) returns()
func (_RegistryAPI *RegistryAPITransactorSession) RegisterDot(dsthash [32]byte, data []byte) (*types.Transaction, error) {
	return _RegistryAPI.Contract.RegisterDot(&_RegistryAPI.TransactOpts, dsthash, data)
}

// RegisterEntity is a paid mutator transaction binding the contract method 0xc93b1335.
//
// Solidity: function registerEntity(data bytes) returns()
func (_RegistryAPI *RegistryAPITransactor) RegisterEntity(opts *bind.TransactOpts, data []byte) (*types.Transaction, error) {
	return _RegistryAPI.contract.Transact(opts, "registerEntity", data)
}

// RegisterEntity is a paid mutator transaction binding the contract method 0xc93b1335.
//
// Solidity: function registerEntity(data bytes) returns()
func (_RegistryAPI *RegistryAPISession) RegisterEntity(data []byte) (*types.Transaction, error) {
	return _RegistryAPI.Contract.RegisterEntity(&_RegistryAPI.TransactOpts, data)
}

// RegisterEntity is a paid mutator transaction binding the contract method 0xc93b1335.
//
// Solidity: function registerEntity(data bytes) returns()
func (_RegistryAPI *RegistryAPITransactorSession) RegisterEntity(data []byte) (*types.Transaction, error) {
	return _RegistryAPI.Contract.RegisterEntity(&_RegistryAPI.TransactOpts, data)
}

// RegisterOffChainDot is a paid mutator transaction binding the contract method 0x427fde4c.
//
// Solidity: function registerOffChainDot(dsthash bytes32, hash bytes32, storageType uint256) returns()
func (_RegistryAPI *RegistryAPITransactor) RegisterOffChainDot(opts *bind.TransactOpts, dsthash [32]byte, hash [32]byte, storageType *big.Int) (*types.Transaction, error) {
	return _RegistryAPI.contract.Transact(opts, "registerOffChainDot", dsthash, hash, storageType)
}

// RegisterOffChainDot is a paid mutator transaction binding the contract method 0x427fde4c.
//
// Solidity: function registerOffChainDot(dsthash bytes32, hash bytes32, storageType uint256) returns()
func (_RegistryAPI *RegistryAPISession) RegisterOffChainDot(dsthash [32]byte, hash [32]byte, storageType *big.Int) (*types.Transaction, error) {
	return _RegistryAPI.Contract.RegisterOffChainDot(&_RegistryAPI.TransactOpts, dsthash, hash, storageType)
}

// RegisterOffChainDot is a paid mutator transaction binding the contract method 0x427fde4c.
//
// Solidity: function registerOffChainDot(dsthash bytes32, hash bytes32, storageType uint256) returns()
func (_RegistryAPI *RegistryAPITransactorSession) RegisterOffChainDot(dsthash [32]byte, hash [32]byte, storageType *big.Int) (*types.Transaction, error) {
	return _RegistryAPI.Contract.RegisterOffChainDot(&_RegistryAPI.TransactOpts, dsthash, hash, storageType)
}

// RegisterRevocation is a paid mutator transaction binding the contract method 0x18c22a6d.
//
// Solidity: function registerRevocation(data bytes) returns()
func (_RegistryAPI *RegistryAPITransactor) RegisterRevocation(opts *bind.TransactOpts, data []byte) (*types.Transaction, error) {
	return _RegistryAPI.contract.Transact(opts, "registerRevocation", data)
}

// RegisterRevocation is a paid mutator transaction binding the contract method 0x18c22a6d.
//
// Solidity: function registerRevocation(data bytes) returns()
func (_RegistryAPI *RegistryAPISession) RegisterRevocation(data []byte) (*types.Transaction, error) {
	return _RegistryAPI.Contract.RegisterRevocation(&_RegistryAPI.TransactOpts, data)
}

// RegisterRevocation is a paid mutator transaction binding the contract method 0x18c22a6d.
//
// Solidity: function registerRevocation(data bytes) returns()
func (_RegistryAPI *RegistryAPITransactorSession) RegisterRevocation(data []byte) (*types.Transaction, error) {
	return _RegistryAPI.Contract.RegisterRevocation(&_RegistryAPI.TransactOpts, data)
}
