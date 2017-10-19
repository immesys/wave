package main

import "github.com/immesys/wave/geth"

func main() {
	geth.Main([]string{"geth", "--verbosity", "6", "console"})

}
