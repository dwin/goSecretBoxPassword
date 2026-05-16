package password

import "errors"

var (
	// ErrCiphertextVer indicates version sub-string mismatch normally; ex. "secBoxv1"
	ErrCiphertextVer = errors.New("nonmatched ciphertext version")
	// ErrCiphertextFormat indicates input is not in expected format
	ErrCiphertextFormat = errors.New("ciphertext input format not as expected")
	// ErrInvalidVersionUpdate indicates new version given not oldVersion + 1 or greater
	ErrInvalidVersionUpdate = errors.New("invalid new version int, new master passphrase version must be greater than previous")
	// ErrPassphraseHashMismatch indicates invalid passphrase for supplied ciphertext
	ErrPassphraseHashMismatch = errors.New("passphrase hash does not match supplied ciphertext")
	// ErrPassphraseLength indicates supplied passphrase is not at least MinLength
	ErrPassphraseLength = errors.New("passphrase must be at least MinLength")
	// ErrSecretBoxDecryptFail indicates SecretBox decryption could not be completed
	ErrSecretBoxDecryptFail = errors.New("secretbox decryption failed")
	// ErrScryptParamN indicates ScryptParams:N out of acceptable range
	ErrScryptParamN = errors.New("given Scrypt (N) cost factor out of acceptable range")
	// ErrScryptParamR indicates ScryptParams:r out of acceptable range
	ErrScryptParamR = errors.New("given Scrypt (r) cost factor out of acceptable range")
	// ErrScryptParamP indicates ScryptParams:p out of acceptable range
	ErrScryptParamP = errors.New("given Scrypt (p) cost factor out of acceptable range")
)
