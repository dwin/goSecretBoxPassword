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
	"testing"
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
}
func TestHash(t *testing.T) {
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

}
func TestGetHashVersion(t *testing.T) {
	v, err := GetHashVersion("secBoxv1$0$tKTBCfdTcn5gA9xRR9yPNczryWV/f+7MVkdDgxFtuYuzvTcNGMNTHBE2pCoPjRjTDIN1449gwVHfrkzvkzWdwZBEUCVWVZFjlRTdu8kCD7uBDmfozwyX+U/T7k8cyfaHFgB8y8cPEvk=$Ek8NWSL34KE=$32768$16$1$16384$8$1")
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	fmt.Println("Hash Version: ", v)
}

func TestGetMasterVersion(t *testing.T) {
	v, err := GetMasterVersion("secBoxv1$0$tKTBCfdTcn5gA9xRR9yPNczryWV/f+7MVkdDgxFtuYuzvTcNGMNTHBE2pCoPjRjTDIN1449gwVHfrkzvkzWdwZBEUCVWVZFjlRTdu8kCD7uBDmfozwyX+U/T7k8cyfaHFgB8y8cPEvk=$Ek8NWSL34KE=$32768$16$1$16384$8$1")
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	fmt.Println("Master Version: ", v)
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
	if err == nil {
		t.Log(err)
		t.FailNow()
	}
}
func TestHashShortPassphrase(t *testing.T) {
	// Errors should not be nil, fail if errors nil
	output, err := Hash("pass", "masterpassphrase", 0, ScryptParams{N: 32768, R: 16, P: 1}, DefaultParams)
	if err == nil {
		t.Log(err)
		t.FailNow()
	}
	t.Log(output)
	output, err = Hash("password1234", "master", 0, ScryptParams{N: 32768, R: 16, P: 1}, DefaultParams)
	if err == nil {
		t.Log(err)
		t.FailNow()
	}
	t.Log(output)
}

func TestVerify(t *testing.T) {
	err := Verify("password1234", "masterpassphrase", "secBoxv1$0$Qk09Tgzi2w+z9mtPiwe6uLWPXMY8WQyI3oC7Sqz11PMcRzvqrOhd70fdBXEUmOeM91z2MytB9Lt4VQzjOs21KTYqMx9FwUR2qDa38fmQhT6pLOJCaptpMzgYLC1fvbq4suuW9XpB7RE=$2ZVcHyy/p9Q=$32768$16$1$16384$8$1")
	if err != nil {
		t.Log(err)
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
