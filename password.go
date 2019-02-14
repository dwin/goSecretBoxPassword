// Package password is a probably paranoid utility library for securly hashing and
// encrypting passwords based on the Dropbox method. This implementation uses Blake2b,
// Scrypt and XSalsa20-Poly1305 (via NaCl SecretBox) to create secure password hashes
// that are also encrypted using a master passphrase. If the master passphrase is lost
// you will lose access to all passwords encrypted with it so store is securely, my
// recommendation is that you store it as an environmental variable or in a config file
// to avoid storing it in source code.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

var (
	// MinLength changes the minimum passphrase and master passphrase length accepted
	MinLength = 8
	// DefaultParams defines Scrypt Parameters
	DefaultParams = ScryptParams{N: 16384, R: 8, P: 1}
)

// ScryptParams sets the Scrypt devivation parameters used for hashing
type ScryptParams struct {
	N int
	R int
	P int
}

// Hash takes passphrase ,masterpassphrase as strings, version indicator as int, and userparams and masterparams as ScryptParams and returns up to 225 char ciphertext string and error - ex. password.Hash("password1234", "masterpassphrase", 0, ScryptParams{N: 32768, R: 16, P: 1}, DefaultParams)
func Hash(userpass, masterpass string, version int, userparams, masterparams ScryptParams) (pwHashOut string, err error) {
	sbpVersion := "v1"
	// Check for non-nil and at least min length password and masterKey
	if len(userpass) < MinLength {
		return "", ErrPassphraseLength
	}
	if len(masterpass) < MinLength {
		return "", ErrPassphraseLength
	}
	// Validate Scrypt Parameters
	err = validateParams(userparams)
	if err != nil {
		return
	}
	err = validateParams(masterparams)
	if err != nil {
		return
	}

	// 1) The plaintext password is transformed into a hash value using Blake2b-512
	userPwBlake := blake2b.Sum512([]byte(userpass))
	// 2) Blake2b hash is hashed again using Scrypt with supplied params plus random 8 byte salt, generating 56 byte output with salt appended for 64 byte total output
	userpassScrypt, err := scryptHash(hex.EncodeToString(userPwBlake[:]), nil, userparams)

	// 3) Encrypt userpass Scrypt output with secretbox XSalsa20-Poly1305 encryption-authentication method using random 24 byte nonce and masterpass Scrypt hash
	encrypted, salt, err := encrypt(masterpass, userpassScrypt, masterparams)
	// 4) Generate base64 of Secretbox output and salt then format output string and return
	ciphertext := base64.StdEncoding.EncodeToString(encrypted)
	saltHex := base64.StdEncoding.EncodeToString(salt)
	pwHashOut = fmt.Sprintf("secBox%s$%v$%s$%s$%v$%v$%v$%v$%v$%v", sbpVersion, version, ciphertext, saltHex, userparams.N, userparams.R, userparams.P, masterparams.N, masterparams.R, masterparams.P)
	return pwHashOut, err
}

// Verify takes passphrase, masterpassphrase and ciphertext as strings and returns error if verification fails, else returns nil upon success
func Verify(userpass, masterpass, ciphertext string) error {
	parts := strings.Split(ciphertext, "$")
	if len(parts) == 10 && parts[0] == "secBoxv1" {
		return verifyV1(userpass, masterpass, parts)
	}
	return ErrCiphertextVer
}

// GetHashVersion takes ciphertext string and returns goSecretBoxPassword version as int and error.
func GetHashVersion(ciphertext string) (version int, err error) {
	parts := strings.Split(ciphertext, "$")
	s := strings.Trim(parts[0], "secBoxv")
	version, err = strconv.Atoi(s)
	if err != nil {
		return
	}
	return
}

// GetParams takes ciphertext string, returns user and master parameters and error. This may be useful for upgrading.
func GetParams(ciphertext string) (userParams, masterParams ScryptParams, err error) {
	parts := strings.Split(ciphertext, "$")
	if len(parts) == 10 && parts[0] == "secBoxv1" {
		return getParams(parts)
	}
	return userParams, masterParams, ErrCiphertextFormat
}

// GetMasterVersion takes ciphertext string and returns master passphrase version as int and error.
func GetMasterVersion(ciphertext string) (version int, err error) {
	parts := strings.Split(ciphertext, "$")
	version, err = strconv.Atoi(parts[1])
	if err != nil {
		return
	}
	return
}

// UpdateMaster takes new master passphrase, old master passphrase as string, new version as int, cipertext as string, and new ScryptParams. It returns and updated hash output string and error.
func UpdateMaster(newMaster, oldMaster string, newVersion int, ciphertext string, masterparams ScryptParams) (pwHashOut string, err error) {
	parts := strings.Split(ciphertext, "$")
	if len(parts) == 10 && parts[0] == "secBoxv1" {
		return updateMasterV1(newMaster, oldMaster, newVersion, parts, masterparams)
	}
	return "", ErrCiphertextFormat
}
func updateMasterV1(newMaster, oldMaster string, newVersion int, parts []string, masterparams ScryptParams) (newHash string, err error) {
	sbpVersion := "v1"
	// Update Secretbox Masterpass version
	cVer, err := strconv.Atoi(parts[1])
	if err != nil {
		return
	}
	if newVersion <= cVer {
		return "", ErrInvalidVersionUpdate
	}
	// Extract Scrypt parameters from string
	userparams, oldMasterparams, err := getParams(parts)
	if err != nil {
		return "", err
	}
	// Regenerate Blake2b-256 hash (32 bytes) using masterpass for secretbox
	//masterpassHash := blake2b.Sum256([]byte(masterpass))
	salt, err := base64.StdEncoding.DecodeString(parts[3])
	masterpassScrypt, err := scryptHash(oldMaster, salt, oldMasterparams)
	if err != nil {
		return "", err
	}
	// Create 32 byte hash of masterpass Scrypt output for Secretbox
	mpScryptB2 := blake2b.Sum256(masterpassScrypt)
	// When you decrypt, you must use the same nonce and key you used to
	// encrypt the message. One way to achieve this is to store the nonce
	// alongside the encrypted message. Above, we stored the nonce in the first
	// 24 bytes of the encrypted text.
	encrypted, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", err
	}
	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])
	decrypted, ok := secretbox.Open(nil, encrypted[24:], &decryptNonce, &mpScryptB2)
	if !ok {
		return "", ErrSecretBoxDecryptFail
	}
	newEncrypted, newSalt, err := encrypt(newMaster, decrypted, masterparams)
	if err != nil {
		return
	}
	// 4) Generate base64 of Secretbox output and salt then format output string and return
	ciphertext := base64.StdEncoding.EncodeToString(newEncrypted)
	saltHex := base64.StdEncoding.EncodeToString(newSalt)
	newHash = fmt.Sprintf("secBox%s$%v$%s$%s$%v$%v$%v$%v$%v$%v", sbpVersion, newVersion, ciphertext, saltHex, userparams.N, userparams.R, userparams.P, masterparams.N, masterparams.R, masterparams.P)
	return
}
func encrypt(masterpass string, userpassScrypt []byte, masterparams ScryptParams) (secretboxOut, salt []byte, err error) {
	// Generate random salt for master passphrase Scrypt hash
	salt = make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic("rand salt failure")
	}
	// Generate Scrypt hash of masterpassphrase
	masterpassScrypt, err := scryptHash(masterpass, salt, masterparams)
	if err != nil {
		return
	}
	// Generate random nonce for secretbox
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic("rand nonce failure")
	}
	// Create 32 byte hash of masterpass Scrypt output for Secretbox
	mpScryptB2 := blake2b.Sum256(masterpassScrypt)
	// Encrypt userpass output and salt using masterpass Scrypt hash as key with the result appended to the nonce.
	secretboxOut = secretbox.Seal(nonce[:], userpassScrypt, &nonce, &mpScryptB2)
	return
}
func verifyV1(userpass, masterpass string, parts []string) (err error) {
	if len(parts) != 10 {
		return ErrCiphertextFormat
	}
	if parts[0] != "secBoxv1" {
		return ErrCiphertextVer
	}
	// Extract Scrypt parameters from string
	userparams, masterparams, err := getParams(parts)
	if err != nil {
		return err
	}
	// Regenerate Blake2b-256 hash (32 bytes) using masterpass for secretbox
	//masterpassHash := blake2b.Sum256([]byte(masterpass))
	salt, err := base64.StdEncoding.DecodeString(parts[3])
	masterpassScrypt, err := scryptHash(masterpass, salt, masterparams)
	if err != nil {
		return err
	}
	// Create 32 byte hash of masterpass Scrypt output for Secretbox
	mpScryptB2 := blake2b.Sum256(masterpassScrypt)
	// When you decrypt, you must use the same nonce and key you used to
	// encrypt the message. One way to achieve this is to store the nonce
	// alongside the encrypted message. Above, we stored the nonce in the first
	// 24 bytes of the encrypted text.
	encrypted, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])
	decrypted, ok := secretbox.Open(nil, encrypted[24:], &decryptNonce, &mpScryptB2)
	if !ok {
		return ErrSecretBoxDecryptFail
	}

	// Use scrypt to derive key for comparison
	// The plaintext password is transformed into a hash value using Blake2b-512
	userPwBlake := blake2b.Sum512([]byte(userpass))
	userpassScrypt, err := scryptHash(hex.EncodeToString(userPwBlake[:]), []byte(decrypted[56:]), userparams)
	if err != nil {
		return err
	}

	// Compare given hash input to generated hash
	if res := subtle.ConstantTimeCompare(decrypted, userpassScrypt); res != 1 {
		// return nil only if supplied hash and computed hash from passphrase match
		return ErrPassphraseHashMismatch
	}

	return err
}
func validateParams(p ScryptParams) error {
	// Cost factor must be multiple of 2
	if p.N < 4096 || p.N > 600000 {
		return ErrScryptParamN
	}
	if p.R < 4 || p.R > 128 {
		return ErrScryptParamR
	}
	if p.P < 1 || p.P > 20 {
		return ErrScryptParamP
	}
	return nil
}

func scryptHash(p string, salt []byte, params ScryptParams) (hash []byte, err error) {
	if salt == nil {
		salt = make([]byte, 8)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			panic("rand salt failure")
		}
	}
	err = validateParams(params)
	if err != nil {
		return nil, err
	}
	// 1) The plaintext password is transformed into a hash value using Blake2b
	hashedPass := blake2b.Sum512([]byte(p))

	// 2) Blake2b hash is hashed again using scrypt with high defaults plus supplied 8 byte salt, generating 56 byte output with salt appended for 64 byte total
	scryptHash, err := scrypt.Key([]byte(hashedPass[:]), salt, params.N, params.R, params.P, 56)
	if err != nil {
		return nil, err
	}
	output := make([]byte, 64)
	copy(output, scryptHash)
	copy(output[56:], salt)
	return output, err
}
func getParams(parts []string) (userparams, masterparams ScryptParams, err error) {
	// Get Scrypt parameters
	userparams.N, err = strconv.Atoi(parts[4])
	if err != nil {
		return
	}
	userparams.R, err = strconv.Atoi(parts[5])
	if err != nil {
		return
	}
	userparams.P, err = strconv.Atoi(parts[6])
	if err != nil {
		return
	}
	err = validateParams(userparams)
	if err != nil {
		return
	}
	masterparams.N, err = strconv.Atoi(parts[7])
	if err != nil {
		return
	}
	masterparams.R, err = strconv.Atoi(parts[8])
	if err != nil {
		return
	}
	masterparams.P, err = strconv.Atoi(parts[9])
	if err != nil {
		return
	}
	err = validateParams(masterparams)
	if err != nil {
		return
	}
	return
}

// Benchmark takes ScryptParams and returns the number of seconds elapsed as a float64 and error
func Benchmark(params ScryptParams) (seconds float64, err error) {
	pw := "benchmarkpass"
	mPw := "benchmarkmasterpass"
	start := time.Now()
	_, err = Hash(pw, mPw, 0, params, DefaultParams)
	if err != nil {
		return 0, err
	}
	t := time.Now()
	elapsed := t.Sub(start)
	return elapsed.Seconds(), err

}

/*
*	goSecretBoxPassword - Golang Password Hashing & Encryption Library
*   Copyright (C) 2017  Darwin Smith
*
*   This program is free software: you can redistribute it and/or modify
*   it under the terms of the GNU General Public License as published by
*   the Free Software Foundation, either version 3 of the License, or
*   (at your option) any later version.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU General Public License for more details.
*
*   You should have received a copy of the GNU General Public License
*   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
