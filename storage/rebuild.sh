#!/bin/bash
../_geth/geth-alltools-linux-amd64-1.7.1-05101641/abigen -abi registry.abi -pkg storage -type registryAPI -out registry.go
../_geth/geth-alltools-linux-amd64-1.7.1-05101641/abigen -abi alias.abi -pkg storage -type aliasAPI -out alias.go
