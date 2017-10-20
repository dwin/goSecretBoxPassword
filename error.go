package password

import "errors"

var (
	// ErrCiphertextVer indicates version sub-string mismatch normally; ex. "secBoxv1"
	ErrCiphertextVer = errors.New("Nonmatched ciphertext version")
	// ErrCiphertextFormat indicates input is not in expected format
	ErrCiphertextFormat = errors.New("Ciphertext input format not as expected")
	// ErrInvalidVersionUpdate indicates new version given not oldVersion + 1 or greater
	ErrInvalidVersionUpdate = errors.New("Invalid new version int, new master passphrase version must be greater than previous")
	// ErrPassphraseHashMismatch indicates invalid passphrase for supplied ciphertext
	ErrPassphraseHashMismatch = errors.New("Passphrase hash does not match supplied ciphertext")
	// ErrPassphraseLength indicates supplied passphrase is not at least MinLength
	ErrPassphraseLength = errors.New("Passphrase must be at least MinLength")
	// ErrSecretBoxDecryptFail indicates SecretBox decryption could not be completed
	ErrSecretBoxDecryptFail = errors.New("SecretBox decryption failed")
	// ErrScryptParamN indicates ScryptParams:N out of acceptable range
	ErrScryptParamN = errors.New("Given Scrypt (N) cost factor out of acceptable range")
	// ErrScryptParamR indicates ScryptParams:r out of acceptable range
	ErrScryptParamR = errors.New("Given Scrypt (r) cost factor out of acceptable range")
	// ErrScryptParamP indicates ScryptParams:p out of acceptable range
	ErrScryptParamP = errors.New("Given Scrypt (p) cost factor out of acceptable range")
)
