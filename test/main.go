package main

import (
	"math/rand"
	"time"

	"github.com/lihongbin99/btls/demo"
	"github.com/lihongbin99/log"
)

func main() {
	rand.Seed(time.Now().Unix())
	log.ChangeLevel("trace")

	demo.SimpleDemo("www.lhb13520.com", 443)
	// demo.CustonHelloClient("www.lhb13520.com", 443)
	// demo.CopyJa3()
}
