package main

import (
	"context"
	"fmt"

	"github.com/immesys/wave/geth"
	"github.com/immesys/wave/storage"
)

func main() {
	go geth.Main([]string{"geth", "--datadir", "/home/immesys/.wave"})
	strg, err := storage.NewEthereumStorage(context.Background(), "/home/immesys/.wave/geth.ipc")
	if err != nil {
		panic(err)
	}
	fmt.Printf("all good\n")
}
