package main

import (
	"fmt"

	password "github.com/dwin/goSecretBoxPassword"
)

var mastPw = "masterpassword" // This should be from config file or environment variables rather than your source

func main() {
	userPw := "userpassword"
	// Hash and encrypt passphrase
	pwHash, err := password.Hash(userPw, mastPw, 0, password.ScryptParams{N: 32768, R: 16, P: 1}, password.DefaultParams)
	if err != nil {
		fmt.Println("Hash fail. ", err)
	}
	// Store pwHash to Database

	// -------- Verify -------------
	// Get pwHash from database and compare to user input using same masterpassword stored hash was created with
	// Verify will return nil unless password does not match or other error occurs
	err = password.Verify(userPw, mastPw, pwHash)
	if err != nil {
		fmt.Println("Verify fail. ", err)
	}
	fmt.Println("Success")
}
