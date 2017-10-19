# goSecretBoxPassword

[![Go Report Card](https://goreportcard.com/badge/github.com/dwin/goSecretBoxPassword)](https://goreportcard.com/report/github.com/dwin/goSecretBoxPassword) [![GoDoc](https://godoc.org/github.com/dwin/goSecretBoxPassword?status.svg)](https://godoc.org/github.com/dwin/goSecretBoxPassword)

This is a Golang library for securing passwords it is based on the [Dropbox method for password storage](https://blogs.dropbox.com/tech/2016/09/how-dropbox-securely-stores-your-passwords/). The both passphrases are first hashed with [Blake2b-512](https://godoc.org/golang.org/x/crypto/blake2b) then a random 64-bit salt is generated and a secure hash is generated using [Scrypt](https://godoc.org/golang.org/x/crypto/scrypt) with the user specified parameters. The salt is appended to resulting 56 byte hash for a total of 64 bytes. The masterpassphrase Scrypt output, which Dropbox describes as a global pepper, is then hashed with Blake2b-256 and is used as a key along with a 192-bit random nonce value for the user passphrase Scrypt output along with Scrypt salt to be encrypted using [NaCl Secretbox](https://godoc.org/golang.org/x/crypto/nacl/secretbox). NaCl Secretbox uses XSalsa20 and Poly1305 to encrypt and authenticate data.

*All hashing and crypto is done by Go library packages. This is only a utility library to make the process described easier.*

The primary changes from the Dropbox method are the use of Blake2b as both a password stretching and hashing method rather than SHA. This provides predictable and acceptable length input for both Scrypt and NaCl Secretbox rather than relying on users to provide sufficient length input. The other changes is the use of NaCl Secretbox using XSalsa20 for encryption and Poly1305 for authentication rather than AES-GCM.

The resulting string is not more than 195 characters in length and contains an identifier, version (used for master passphrase version), the ciphertext Scrypt base-64 value, masterkey Scrypt salt as base-64, and user passphrase scrypt parameters as integers, followed by master passphrase Scrypt parameters in the same format with each section seperated by '$'. The master passphrase is not recommended to be stored with the passwords, you may choose to store this value in many ways, but understand that loosing the masterpassphrase will cause you to lose access to all passwords encrypted with this. According to the math, you should be able to use the same master passphrase for several quintillion passphrases without key exhaustion using XSalsa20 so you should feel free to use it for all users rather than attempting to rotate this. You can store the master passphrase and an environmental variable, CLI argument or come up with your own novel approach as long as you don't lose it. Using this method, even if the user credential database were to be compromised the attacker would first need to break the Secretbox encryption before being able to then attempt to crack the Scrypt passphrase hashes which would still only reveal the Blake2b-512 hash of the passphrase. By tuning the Scrypt parameters you can make the password hash derivation more costly (more time and resource consuming). You will need to balance security and speed. As of writing, secure recommendations for interactive logins are N=32768, r=8 and p=1. The parameters N, r, and p should be increased as memory latency and CPU parallelism increases; consider setting N to the highest power of 2 you can derive within an acceptable period of time. Because these parameters are combined to be stored with the output you should have no issue changing the settings without forcing users to update. Their is also a version tag included to allow for future library updates without causing breaking changes for existing users.

*The params are used for both the user passphrase and master passphrase hash, keep in mind that any settings is being done twice as thus Scrypt hashing params have twice the impact. I have considered creating an updated version where master or user passphrase hash is computed using a different algorithm or with different parameters to increase speed. This would not be a breaking change since there is a version included in all hash outputs.*

Example Output:

```secBoxv1$0$G0Ke6q1upuoC+fs+cPvK5swmF8WNNxc9cWHwyp5pZtL/Yc+KmjD1x/43mjy/ySWj4uAFc92LL5tKmvsTCedFMqyNJ8URdzJ1MgdqmCgMIkOXy87JacKdLnxjyIWjeeNnLVxiCWjXhrI=$8OPoOpUeIf0=$32768$16$1$16384$8$1```

## Usage

Tagged Stable Version from [GoPkg](http://gopkg.in/dwin/goSecretBoxPassword.v1):

```bash
go get gopkg.in/dwin/goSecretBoxPassword.v1
```

```go
import "gopkg.in/dwin/goSecretBoxPassword.v1"
```

Latest from Github:

```bash
go get github.com/dwin/goSecretBoxPassword
```

```go
import "github.com/dwin/goSecretBoxPassword"
```

### Future Plans

- [x] Helper function for updating master passphrase without modifying user passphrase
- [x] Allow seamless change of master passphrase using version code
- [x] ~~Allow disable of Scrypt~~, use of different parameters ~~or algorithm~~ for master passphrase hash to increase speed or security

### Example

```go
package main

import (
    "fmt"

    password "github.com/dwin/goSecretBoxPassword"
)

// This should be from config file or environemnt variables rather than your source
var mastPw = "masterpassword" 

func main() {
    userPw := "userpassword"
    // Hash and encrypt passphrase
    pwHash, err := password.Hash(userPw, mastPw, 0, password.ScryptParams{N: 32768, R: 16, P: 1}, password.DefaultParams)
    if err != nil {
        fmt.Println("Hash fail. ", err)
    }
   // Store pwHash to Database ->

    // -------- Verify -------------
    // Get pwHash from database <- and compare to user input using same
    // masterpassword stored hash was created with.
    // Verify will return nil unless password does not match or other error occurs
    err = password.Verify(userPw, mastPw, pwHash)
    if err != nil {
        fmt.Println("Verify fail. ", err)
    }
    fmt.Println("Success")
}
```
