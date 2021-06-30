package main

import (
	"crypto/rand"
	"math/big"
)

func main() {
}

func getSerial() (*big.Int, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return big.NewInt(0), err
	}
	return serial, nil
}
