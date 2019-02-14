/*
	goSecretBoxPassword - Golang Password Hashing & Encryption Library
    Copyright (C) 2017  Darwin Smith

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package password

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func TestBench(t *testing.T) {
	// 2<<14 = 16384
	params := ScryptParams{N: 2 << 14, R: 8, P: 1}
	runs := 10
	total := 0.0
	for i := 0; i < runs; i++ {
		result, err := Benchmark(params)
		if err != nil {
			t.Log(err)
			t.FailNow()
		}
		total += result
	}

	fmt.Printf("Benchmark Result (avg): %v of %v runs, with Scrypt params: N:%v R:%v P:%v\n", total/float64(runs), runs, params.N, params.R, params.P)

	// Test Bench hash error
	result, err := Benchmark(ScryptParams{N: 2048, R: 8, P: 1})
	if err != ErrScryptParamN && result != 0 {
		t.Log(err)
		t.FailNow()
	}
}

var src = rand.NewSource(time.Now().UnixNano())

const (
	chars         = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+<>?/,.:;[]-~`"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func RandStringBytesMaskImprSrc(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(chars) {
			b[i] = chars[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

func TestHash(t *testing.T) {

	var total int
	runs := 52
	// Test expect success
	for i := 2; i < runs; i++ {
		// Generate Test Password
		testUserPass := RandStringBytesMaskImprSrc(i * 4)
		testMasterPass := RandStringBytesMaskImprSrc(i * 4)
		// Hash Password
		output, err := Hash(testUserPass, testMasterPass, 0, ScryptParams{N: 32768, R: 16, P: 1}, DefaultParams)
		if err != nil {
			t.Log(err)
			t.FailNow()
		}
		t.Logf("Output: " + output)

		// Check Output Length
		lgth := len(output)
		if lgth > 225 {
			t.Logf("Output Length over 225 chars at %v for input userpass length %v", lgth, len(testUserPass))
		}
		total = total + lgth

		// Verify Password
		if err := Verify(testUserPass, testMasterPass, output); err != nil {
			t.Log(err)
			t.FailNow()
		}
	}
	fmt.Printf("Average length of %v runs: %v\n", runs, total/runs)

	// Test with Bad Params
	_, err := Hash("password1234", "masterpassphrase", 0, ScryptParams{N: 2048, R: 16, P: 1}, DefaultParams)
	if err != ErrScryptParamN {
		t.Log("Expected Scrypt N failure for user params")
		t.FailNow()
	}
	_, err = Hash("password1234", "masterpassphrase", 0, DefaultParams, ScryptParams{N: 2048, R: 16, P: 1})
	if err != ErrScryptParamN {
		t.Log("Expected Scrypt N failure for master params")
		t.FailNow()
	}

}
func TestGetHashVersion(t *testing.T) {
	v, err := GetHashVersion("secBoxv1$0$tKTBCfdTcn5gA9xRR9yPNczryWV/f+7MVkdDgxFtuYuzvTcNGMNTHBE2pCoPjRjTDIN1449gwVHfrkzvkzWdwZBEUCVWVZFjlRTdu8kCD7uBDmfozwyX+U/T7k8cyfaHFgB8y8cPEvk=$Ek8NWSL34KE=$32768$16$1$16384$8$1")
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	fmt.Println("Hash Version: ", v)

	// Test with Bad Version; secBoxvb instead of expected secBoxv1
	_, err = GetHashVersion("secBoxvb$0$tKTBCfdTcn5gA9xRR9yPNczryWV/f+7MVkdDgxFtuYuzvTcNGMNTHBE2pCoPjRjTDIN1449gwVHfrkzvkzWdwZBEUCVWVZFjlRTdu8kCD7uBDmfozwyX+U/T7k8cyfaHFgB8y8cPEvk=$Ek8NWSL34KE=$32768$16$1$16384$8$1")
	if err == nil {
		t.Log("Expected int parse from string error")
		t.FailNow()
	}
}

func TestGetMasterVersion(t *testing.T) {
	v, err := GetMasterVersion("secBoxv1$0$tKTBCfdTcn5gA9xRR9yPNczryWV/f+7MVkdDgxFtuYuzvTcNGMNTHBE2pCoPjRjTDIN1449gwVHfrkzvkzWdwZBEUCVWVZFjlRTdu8kCD7uBDmfozwyX+U/T7k8cyfaHFgB8y8cPEvk=$Ek8NWSL34KE=$32768$16$1$16384$8$1")
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	fmt.Println("Master Version: ", v)

	// Test Bad Master Version; x instead of 0
	_, err = GetMasterVersion("secBoxv1$x$tKTBCfdTcn5gA9xRR9yPNczryWV/f+7MVkdDgxFtuYuzvTcNGMNTHBE2pCoPjRjTDIN1449gwVHfrkzvkzWdwZBEUCVWVZFjlRTdu8kCD7uBDmfozwyX+U/T7k8cyfaHFgB8y8cPEvk=$Ek8NWSL34KE=$32768$16$1$16384$8$1")
	if err == nil {
		t.Log("Expected string to int parse failure")
		t.FailNow()
	}
}
func TestGetParamsFromHash(t *testing.T) {
	user, master, err := GetParams("secBoxv1$1$5DxIID0p4uz073qNngNsxYhXKPJITbjdvpjLju/XKbbzKDjdXVvgCSVbNIjCAg2QvA8O4mC+/fZpExJJx9rVpgxeL4xH16kN5/AGHtaa3kPNlP0tB5dJjDbFsJVr7u/ar9v4hzwQYhk=$xGvsvszfJDY=$32768$16$1$16384$8$1")
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	fmt.Printf("From Hash-> User Params: N-%v R-%v P-%v Master Params: N-%v R-%v P-%v\n", user.N, user.R, user.P, master.N, master.R, master.P)

	// Test with Bad Format
	user, master, err = GetParams("secBoxv1$5DxIID0p4uz073qNngNsxYhXKPJITbjdvpjLju/XKbbzKDjdXVvgCSVbNIjCAg2QvA8O4mC+/fZpExJJx9rVpgxeL4xH16kN5/AGHtaa3kPNlP0tB5dJjDbFsJVr7u/ar9v4hzwQYhk=$xGvsvszfJDY=$32768$16$1$16384$8$1")
	if err != ErrCiphertextFormat {
		t.Log("Expected invalid format error")
		t.FailNow()
	}
}
func TestGetParams(t *testing.T) {
	parts := []string{"0", "1", "2", "3", "8192", "8", "1", "8192", "8", "1"}
	user, master, err := getParams(parts)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	if user.N != 8192 || user.R != 8 || user.P != 1 {
		t.Log("Returned parameters do not match given")
		t.FailNow()
	}
	if master.N != 8192 || master.R != 8 || master.P != 1 {
		t.Log("Returned parameters do not match given")
		t.FailNow()
	}
	fmt.Printf("User Params: N-%v R-%v P-%v Master Params: N-%v R-%v P-%v\n", user.N, user.R, user.P, master.N, master.R, master.P)

	// Invalid Params parts[4]-parts[9], should return err for each
	for i := 4; i < len(parts); i++ {
		parts = []string{"0", "1", "2", "3", "8192", "8", "1", "8192", "8", "1"}

		parts[i] = "x"
		user, master, err = getParams(parts)
		if err == nil {
			t.Log(err)
			t.FailNow()
		}
	}

}
func TestUpdateMaster(t *testing.T) {
	output, err := Hash("password1234", "masterpassphrase", 0, ScryptParams{N: 32768, R: 16, P: 1}, DefaultParams)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	fmt.Println("Output: " + output)
	fmt.Printf("Length: %v\n", len(output))

	err = Verify("password1234", "masterpassphrase", output)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	// Update then re-verify
	updated, err := UpdateMaster("masterpassphrase2", "masterpassphrase", 1, output, DefaultParams)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	fmt.Println("Updated Output: " + updated)
	fmt.Printf("Updated Length: %v\n", len(updated))
	err = Verify("password1234", "masterpassphrase2", updated)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	// Test Bad Format Fail
	_, err = UpdateMaster("masterpassphrase2", "masterpassphrase", 1, "secBoxv1$l8W69jygGur7sa0669mAJnIuYgjsbkx4wd+RdDzwIn2Z49FJurWkJDx2NA8g+ED9Nn6vGCLNFoHXSDIDeDBvJXouxs5zyX6mVozceVAVO7IadrL4+KKohV3MzoVlgodUYeNToOVB/5A=$4LZVjQ8P9pA=$32768$16$1$16384$8$1", DefaultParams)
	if err != ErrCiphertextFormat {
		t.Log("Expected Ciphertext format failure")
		t.FailNow()
	}

	// Test Bad Params Fail
	_, err = UpdateMaster("masterpassphrase2", "masterpassphrase", 1, "secBoxv1$0$l8W69jygGur7sa0669mAJnIuYgjsbkx4wd+RdDzwIn2Z49FJurWkJDx2NA8g+ED9Nn6vGCLNFoHXSDIDeDBvJXouxs5zyX6mVozceVAVO7IadrL4+KKohV3MzoVlgodUYeNToOVB/5A=$4LZVjQ8P9pA=$32768$16$1$16384$8$1", ScryptParams{N: 2048, R: 8, P: 1})
	if err != ErrScryptParamN {
		t.Log(err)
		t.Log("Expected Scrypt N param failure")
		t.FailNow()
	}

	// Test Bad Old Master passphrase, decrypt fail
	_, err = UpdateMaster("masterpassphrase2", "incorrectmaster", 1, "secBoxv1$0$l8W69jygGur7sa0669mAJnIuYgjsbkx4wd+RdDzwIn2Z49FJurWkJDx2NA8g+ED9Nn6vGCLNFoHXSDIDeDBvJXouxs5zyX6mVozceVAVO7IadrL4+KKohV3MzoVlgodUYeNToOVB/5A=$4LZVjQ8P9pA=$32768$16$1$16384$8$1", DefaultParams)
	if err != ErrSecretBoxDecryptFail {
		t.Log(err)
		t.Log("Expected decryption failure")
		t.FailNow()
	}
}
func TestUpdateMasterBadVersion(t *testing.T) {
	output, err := Hash("password1234", "masterpassphrase", 0, ScryptParams{N: 32768, R: 16, P: 1}, DefaultParams)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	fmt.Println("Output: " + output)
	fmt.Printf("Length: %v\n", len(output))

	err = Verify("password1234", "masterpassphrase", output)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	// Update then re-verify
	_, err = UpdateMaster("masterpassphrase2", "masterpassphrase", 0, output, DefaultParams)
	if err != ErrInvalidVersionUpdate {
		t.Log("Expected Invalid Version update error")
		t.FailNow()
	}
}
func TestHashShortPassphrase(t *testing.T) {
	// Errors should not be nil, fail if errors nil
	_, err := Hash("pass", "masterpassphrase", 0, ScryptParams{N: 32768, R: 16, P: 1}, DefaultParams)
	if err != ErrPassphraseLength {
		t.Log("Expected Passphrase length failure")
		t.FailNow()
	}

	_, err = Hash("password1234", "master", 0, ScryptParams{N: 32768, R: 16, P: 1}, DefaultParams)
	if err != ErrPassphraseLength {
		t.Log("Expected Passphrase length failure")
		t.FailNow()
	}

}

func TestVerify(t *testing.T) {
	err := Verify("password1234", "masterpassphrase", "secBoxv1$0$Qk09Tgzi2w+z9mtPiwe6uLWPXMY8WQyI3oC7Sqz11PMcRzvqrOhd70fdBXEUmOeM91z2MytB9Lt4VQzjOs21KTYqMx9FwUR2qDa38fmQhT6pLOJCaptpMzgYLC1fvbq4suuW9XpB7RE=$2ZVcHyy/p9Q=$32768$16$1$16384$8$1")
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
}
func TestVerifyV1(t *testing.T) {
	// Fail Length
	err := verifyV1("password1234", "masterpassphrase", []string{"secBoxv1", "Qk09Tgzi2w+z9mtPiwe6uLWPXMY8WQyI3oC7Sqz11PMcRzvqrOhd70fdBXEUmOeM91z2MytB9Lt4VQzjOs21KTYqMx9FwUR2qDa38fmQhT6pLOJCaptpMzgYLC1fvbq4suuW9XpB7RE=", "2ZVcHyy/p9Q=", "32768", "16", "1", "16384", "8", "1"})
	if err != ErrCiphertextFormat {
		t.Log("Expected Format Failure")
		t.FailNow()
	}
	// Fail ciphertext version check
	err = verifyV1("password1234", "masterpassphrase", []string{"secBoxv0", "0", "Qk09Tgzi2w+z9mtPiwe6uLWPXMY8WQyI3oC7Sqz11PMcRzvqrOhd70fdBXEUmOeM91z2MytB9Lt4VQzjOs21KTYqMx9FwUR2qDa38fmQhT6pLOJCaptpMzgYLC1fvbq4suuW9XpB7RE=", "2ZVcHyy/p9Q=", "32768", "16", "1", "16384", "8", "1"})
	if err != ErrCiphertextVer {
		t.Log("Expect Version Failure")
		t.FailNow()
	}
}
func TestVerifyFormat(t *testing.T) {
	err := Verify("password", "masterpassphrase", "secBoxv1$0$Qk09Tgzi2w+z9mtPiwe6uLWPXMY8WQyI3oC7Sqz11PMcRzvqrOhd70fdBXEUmOeM91z2MytB9Lt4VQzjOs21KTYqMx9FwUR2qDa38fmQhT6pLOJCaptpMzgYLC1fvbq4suuW9XpB7RE=$2ZVcHyy/p9Q=$32768$16$1$16384$8$1")
	if err == nil {
		t.Log(err)
		t.FailNow()
	}
}

func TestVerifyVersion(t *testing.T) {
	err := Verify("password", "masterpassphrase", "secBoxv0$0$Qk09Tgzi2w+z9mtPiwe6uLWPXMY8WQyI3oC7Sqz11PMcRzvqrOhd70fdBXEUmOeM91z2MytB9Lt4VQzjOs21KTYqMx9FwUR2qDa38fmQhT6pLOJCaptpMzgYLC1fvbq4suuW9XpB7RE=$2ZVcHyy/p9Q=$32768$16$1$16384$8$1")
	if err == nil {
		t.Log(err)
		t.FailNow()
	}
}

func TestVerifyParseParams(t *testing.T) {
	// These should fail if errors are not returned
	err := Verify("password", "masterpassphrase", "secBoxv0$0$Qk09Tgzi2w+z9mtPiwe6uLWPXMY8WQyI3oC7Sqz11PMcRzvqrOhd70fdBXEUmOeM91z2MytB9Lt4VQzjOs21KTYqMx9FwUR2qDa38fmQhT6pLOJCaptpMzgYLC1fvbq4suuW9XpB7RE=$2ZVcHyy/p9Q=$32768$16$1$16384$8$a")
	if err == nil {
		t.Log(err)
		t.FailNow()
	}
	err = Verify("password", "masterpassphrase", "secBoxv0$0$Qk09Tgzi2w+z9mtPiwe6uLWPXMY8WQyI3oC7Sqz11PMcRzvqrOhd70fdBXEUmOeM91z2MytB9Lt4VQzjOs21KTYqMx9FwUR2qDa38fmQhT6pLOJCaptpMzgYLC1fvbq4suuW9XpB7RE=$2ZVcHyy/p9Q=$32768$16$1$16384$b$1")
	if err == nil {
		t.Log(err)
		t.FailNow()
	}
	err = Verify("password", "masterpassphrase", "secBoxv0$0$Qk09Tgzi2w+z9mtPiwe6uLWPXMY8WQyI3oC7Sqz11PMcRzvqrOhd70fdBXEUmOeM91z2MytB9Lt4VQzjOs21KTYqMx9FwUR2qDa38fmQhT6pLOJCaptpMzgYLC1fvbq4suuW9XpB7RE=$2ZVcHyy/p9Q=$32768$16$1$c$b$1")
	if err == nil {
		t.Log(err)
		t.FailNow()
	}
}

func TestVerifyBadParams(t *testing.T) {
	err := Verify("password", "masterpassphrase", "secBoxv0$0$Qk09Tgzi2w+z9mtPiwe6uLWPXMY8WQyI3oC7Sqz11PMcRzvqrOhd70fdBXEUmOeM91z2MytB9Lt4VQzjOs21KTYqMx9FwUR2qDa38fmQhT6pLOJCaptpMzgYLC1fvbq4suuW9XpB7RE=$2ZVcHyy/p9Q=$32768$16$1$16384$999$1")
	if err == nil {
		t.Log(err)
		t.FailNow()
	}
}
func TestVerifyBadPassphrase(t *testing.T) {
	err := Verify("passw0rd", "masterpassphrase", "secBoxv1$0$Qk09Tgzi2w+z9mtPiwe6uLWPXMY8WQyI3oC7Sqz11PMcRzvqrOhd70fdBXEUmOeM91z2MytB9Lt4VQzjOs21KTYqMx9FwUR2qDa38fmQhT6pLOJCaptpMzgYLC1fvbq4suuW9XpB7RE=$2ZVcHyy/p9Q=$32768$16$1$16384$8$1")
	if err == nil {
		t.Log(err)
		t.FailNow()
	}
}
func TestVerifyBadMasterPass(t *testing.T) {
	err := Verify("password", "mast3rpassphrase", "secBoxv1$0$Qk09Tgzi2w+z9mtPiwe6uLWPXMY8WQyI3oC7Sqz11PMcRzvqrOhd70fdBXEUmOeM91z2MytB9Lt4VQzjOs21KTYqMx9FwUR2qDa38fmQhT6pLOJCaptpMzgYLC1fvbq4suuW9XpB7RE=$2ZVcHyy/p9Q=$32768$16$1$16384$8$1")
	if err == nil {
		t.Log(err)
		t.FailNow()
	}
}
func TestVerifyBadSalt(t *testing.T) {
	err := Verify("password", "mast3rpassphrase", "secBoxv1$0$Qk09Tgzi2w+z9mtPiwe6uLWPXMY8WQyI3oC7Sqz11PMcRzvqrOhd70fdBXEUmOeM91z2MytB9Lt4VQzjOs21KTYqMx9FwUR2qDa38fmQhT6pLOJCaptpMzgYLC1fvbq4suuW9XpB7RE=$2ZVbHyy/p9Q=$32768$16$1$16384$8$1")
	if err == nil {
		t.Log(err)
		t.FailNow()
	}
}
func TestValidateParams(t *testing.T) {
	// This should pass
	err := validateParams(ScryptParams{N: 65536, R: 32, P: 2})
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	// These should fail
	err = validateParams(ScryptParams{N: 10, R: 32, P: 2})
	if err == nil {
		t.Log(err)
		t.FailNow()
	}

	err = validateParams(ScryptParams{N: 601000, R: 32, P: 2})
	if err == nil {
		t.Log(err)
		t.FailNow()
	}

	err = validateParams(ScryptParams{N: 32500, R: 2, P: 2})
	if err == nil {
		t.Log(err)
		t.FailNow()
	}

	err = validateParams(ScryptParams{N: 32500, R: 130, P: 2})
	if err == nil {
		t.Log(err)
		t.FailNow()
	}

	err = validateParams(ScryptParams{N: 32500, R: 32, P: 0})
	if err == nil {
		t.Log(err)
		t.FailNow()
	}

	err = validateParams(ScryptParams{N: 32500, R: 32, P: 22})
	if err == nil {
		t.Log(err)
		t.FailNow()
	}
}
