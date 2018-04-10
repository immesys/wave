package main

import (
	"os"

	"github.com/immesys/wave/storage/persistentserver"
)

func main() {
	persistentserver.Main(os.Args)
}
