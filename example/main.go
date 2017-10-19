package main

import (
	"fmt"

	password "github.com/dwin/goSecretBoxPassword"
)

// These should be from config file or environment variables rather than your source
var mastPw0 = "masterpassword"
var mastPw1 = "masterpassword1"

func main() {
	userPw := "userpassword"
	// Hash and encrypt passphrase
	pwHash, err := password.Hash(userPw, mastPw0, 0, password.ScryptParams{N: 32768, R: 16, P: 1}, password.DefaultParams)
	if err != nil {
		fmt.Println("Hash fail. ", err)
	}
	// Store pwHash to Database

	// -------- Verify -------------
	// Get pwHash from database and compare to user input using same masterpassword stored hash was created with
	// Verify will return nil unless password does not match or other error occurs
	err = password.Verify(userPw, mastPw0, pwHash)
	if err != nil {
		fmt.Println("Verify fail. ", err)
	}
	fmt.Println("Success")

	// --------- Update ------------
	// Get pwhash from database and update using new masterpassphrase, version, and parameters
	updated, err := password.UpdateMaster(mastPw1, mastPw0, 1, pwHash, password.DefaultParams)
	if err != nil {
		fmt.Println("Update fail. ", err)
	}
	err = password.Verify(userPw, mastPw1, updated)
	if err != nil {
		fmt.Println("Verify fail. ", err)
	}
	fmt.Println("Success verifying updated hash")
}
