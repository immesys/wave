// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package storage

import (
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// AliasAPIABI is the input ABI used to generate the binding from.
const AliasAPIABI = "[{\"constant\":false,\"inputs\":[{\"name\":\"tld\",\"type\":\"bytes32\"},{\"name\":\"domain\",\"type\":\"bytes32\"},{\"name\":\"subdomain\",\"type\":\"bytes32\"},{\"name\":\"value\",\"type\":\"bytes\"}],\"name\":\"CreateSubdomain\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"tld\",\"type\":\"bytes32\"}],\"name\":\"CreateTLD\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"toplevels\",\"outputs\":[{\"name\":\"controller\",\"type\":\"address\",\"value\":\"0x0000000000000000000000000000000000000000\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"}]"

// AliasAPI is an auto generated Go binding around an Ethereum contract.
type AliasAPI struct {
	AliasAPICaller     // Read-only binding to the contract
	AliasAPITransactor // Write-only binding to the contract
}

// AliasAPICaller is an auto generated read-only Go binding around an Ethereum contract.
type AliasAPICaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AliasAPITransactor is an auto generated write-only Go binding around an Ethereum contract.
type AliasAPITransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AliasAPISession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type AliasAPISession struct {
	Contract     *AliasAPI         // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// AliasAPICallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type AliasAPICallerSession struct {
	Contract *AliasAPICaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts   // Call options to use throughout this session
}

// AliasAPITransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type AliasAPITransactorSession struct {
	Contract     *AliasAPITransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// AliasAPIRaw is an auto generated low-level Go binding around an Ethereum contract.
type AliasAPIRaw struct {
	Contract *AliasAPI // Generic contract binding to access the raw methods on
}

// AliasAPICallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type AliasAPICallerRaw struct {
	Contract *AliasAPICaller // Generic read-only contract binding to access the raw methods on
}

// AliasAPITransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type AliasAPITransactorRaw struct {
	Contract *AliasAPITransactor // Generic write-only contract binding to access the raw methods on
}

// NewAliasAPI creates a new instance of AliasAPI, bound to a specific deployed contract.
func NewAliasAPI(address common.Address, backend bind.ContractBackend) (*AliasAPI, error) {
	contract, err := bindAliasAPI(address, backend, backend)
	if err != nil {
		return nil, err
	}
	return &AliasAPI{AliasAPICaller: AliasAPICaller{contract: contract}, AliasAPITransactor: AliasAPITransactor{contract: contract}}, nil
}

// NewAliasAPICaller creates a new read-only instance of AliasAPI, bound to a specific deployed contract.
func NewAliasAPICaller(address common.Address, caller bind.ContractCaller) (*AliasAPICaller, error) {
	contract, err := bindAliasAPI(address, caller, nil)
	if err != nil {
		return nil, err
	}
	return &AliasAPICaller{contract: contract}, nil
}

// NewAliasAPITransactor creates a new write-only instance of AliasAPI, bound to a specific deployed contract.
func NewAliasAPITransactor(address common.Address, transactor bind.ContractTransactor) (*AliasAPITransactor, error) {
	contract, err := bindAliasAPI(address, nil, transactor)
	if err != nil {
		return nil, err
	}
	return &AliasAPITransactor{contract: contract}, nil
}

// bindAliasAPI binds a generic wrapper to an already deployed contract.
func bindAliasAPI(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(AliasAPIABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AliasAPI *AliasAPIRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _AliasAPI.Contract.AliasAPICaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AliasAPI *AliasAPIRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AliasAPI.Contract.AliasAPITransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AliasAPI *AliasAPIRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AliasAPI.Contract.AliasAPITransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AliasAPI *AliasAPICallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _AliasAPI.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AliasAPI *AliasAPITransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AliasAPI.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AliasAPI *AliasAPITransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AliasAPI.Contract.contract.Transact(opts, method, params...)
}

// Toplevels is a free data retrieval call binding the contract method 0xde3f1fd0.
//
// Solidity: function toplevels( bytes32) constant returns(controller address)
func (_AliasAPI *AliasAPICaller) Toplevels(opts *bind.CallOpts, arg0 [32]byte) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := ret0
	err := _AliasAPI.contract.Call(opts, out, "toplevels", arg0)
	return *ret0, err
}

// Toplevels is a free data retrieval call binding the contract method 0xde3f1fd0.
//
// Solidity: function toplevels( bytes32) constant returns(controller address)
func (_AliasAPI *AliasAPISession) Toplevels(arg0 [32]byte) (common.Address, error) {
	return _AliasAPI.Contract.Toplevels(&_AliasAPI.CallOpts, arg0)
}

// Toplevels is a free data retrieval call binding the contract method 0xde3f1fd0.
//
// Solidity: function toplevels( bytes32) constant returns(controller address)
func (_AliasAPI *AliasAPICallerSession) Toplevels(arg0 [32]byte) (common.Address, error) {
	return _AliasAPI.Contract.Toplevels(&_AliasAPI.CallOpts, arg0)
}

// CreateSubdomain is a paid mutator transaction binding the contract method 0x4ef3b3cc.
//
// Solidity: function CreateSubdomain(tld bytes32, domain bytes32, subdomain bytes32, value bytes) returns()
func (_AliasAPI *AliasAPITransactor) CreateSubdomain(opts *bind.TransactOpts, tld [32]byte, domain [32]byte, subdomain [32]byte, value []byte) (*types.Transaction, error) {
	return _AliasAPI.contract.Transact(opts, "CreateSubdomain", tld, domain, subdomain, value)
}

// CreateSubdomain is a paid mutator transaction binding the contract method 0x4ef3b3cc.
//
// Solidity: function CreateSubdomain(tld bytes32, domain bytes32, subdomain bytes32, value bytes) returns()
func (_AliasAPI *AliasAPISession) CreateSubdomain(tld [32]byte, domain [32]byte, subdomain [32]byte, value []byte) (*types.Transaction, error) {
	return _AliasAPI.Contract.CreateSubdomain(&_AliasAPI.TransactOpts, tld, domain, subdomain, value)
}

// CreateSubdomain is a paid mutator transaction binding the contract method 0x4ef3b3cc.
//
// Solidity: function CreateSubdomain(tld bytes32, domain bytes32, subdomain bytes32, value bytes) returns()
func (_AliasAPI *AliasAPITransactorSession) CreateSubdomain(tld [32]byte, domain [32]byte, subdomain [32]byte, value []byte) (*types.Transaction, error) {
	return _AliasAPI.Contract.CreateSubdomain(&_AliasAPI.TransactOpts, tld, domain, subdomain, value)
}

// CreateTLD is a paid mutator transaction binding the contract method 0xb44bbd25.
//
// Solidity: function CreateTLD(tld bytes32) returns()
func (_AliasAPI *AliasAPITransactor) CreateTLD(opts *bind.TransactOpts, tld [32]byte) (*types.Transaction, error) {
	return _AliasAPI.contract.Transact(opts, "CreateTLD", tld)
}

// CreateTLD is a paid mutator transaction binding the contract method 0xb44bbd25.
//
// Solidity: function CreateTLD(tld bytes32) returns()
func (_AliasAPI *AliasAPISession) CreateTLD(tld [32]byte) (*types.Transaction, error) {
	return _AliasAPI.Contract.CreateTLD(&_AliasAPI.TransactOpts, tld)
}

// CreateTLD is a paid mutator transaction binding the contract method 0xb44bbd25.
//
// Solidity: function CreateTLD(tld bytes32) returns()
func (_AliasAPI *AliasAPITransactorSession) CreateTLD(tld [32]byte) (*types.Transaction, error) {
	return _AliasAPI.Contract.CreateTLD(&_AliasAPI.TransactOpts, tld)
}
