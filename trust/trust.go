package trust

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
)

func GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, 4096)
	return privkey, &privkey.PublicKey
}

func ExportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey) string {
	privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
	privkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkey_bytes,
		},
	)
	return string(privkey_pem)
}

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)

	return string(pubkey_pem), nil
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}

func GenerateRsaKeyPairIfNotExist(privKeyFile string, pubKeyFile string, save bool) (*rsa.PrivateKey, *rsa.PublicKey) {
	found := true
	if _, err := os.Stat("keystore/" + privKeyFile); os.IsNotExist(err) {
		found = false
		path, err := os.Getwd()
		if err != nil {
			panic(err)
		}
		_ = os.Mkdir(path+"/keystore", os.ModePerm)
	}
	if _, err := os.Stat("keystore/" + pubKeyFile); os.IsNotExist(err) {
		found = false
		path, err := os.Getwd()
		if err != nil {
			panic(err)
		}
		_ = os.Mkdir(path+"/keystore", os.ModePerm)
	}
	if !found {
		fmt.Println("*********************************************************")
		fmt.Printf("Rsa Key files (%s, %s) not found, regenerating.\n", privKeyFile, pubKeyFile)
		priv, pub := GenerateRsaKeyPair()
		privStr := ExportRsaPrivateKeyAsPemStr(priv)
		pubStr, _ := ExportRsaPublicKeyAsPemStr(pub)
		if save {
			fpri, err := os.Create("keystore/" + privKeyFile)
			if err != nil {
				panic(err)
			}
			defer fpri.Close()
			fpri.WriteString(privStr)

			fpub, err := os.Create("keystore/" + pubKeyFile)
			if err != nil {
				panic(err)
			}
			defer fpub.Close()
			fpub.WriteString(pubStr)
			fmt.Printf("Saving RSA key pairs to %s and %s.\n", privKeyFile, pubKeyFile)
		}
		return priv, pub
	}
	priStr, err := ioutil.ReadFile("keystore/" + privKeyFile)
	if err != nil {
		panic(err)
	}
	pubStr, err := ioutil.ReadFile("keystore/" + pubKeyFile)
	if err != nil {
		panic(err)
	}
	// fmt.Printf("Reading RSA key pairs from %s and %s.\n", privKeyFile, pubKeyFile)
	priv, err := ParseRsaPrivateKeyFromPemStr(string(priStr))
	if err != nil {
		panic(err)
	}
	pub, err := ParseRsaPublicKeyFromPemStr(string(pubStr))
	if err != nil {
		panic(err)
	}
	return priv, pub

}

// RSAEncrypt : Encrypt the value with rsa algo.
func RSAEncrypt(key *rsa.PublicKey, val string) (code string, err error) {
	c, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, []byte(val), nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	code = base64.StdEncoding.EncodeToString(c)
	return
}

// RSADecrypt : Decrypt the value with rsa algo.
func RSADecrypt(key *rsa.PrivateKey, code string) (val string, err error) {
	ciphertext := make([]byte, base64.StdEncoding.DecodedLen(len(code)))
	n, err := base64.StdEncoding.Decode(ciphertext, []byte(code))
	if err != nil {
		return
	}
	ciphertext = ciphertext[:n]

	ret, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	val = string(ret)
	return
}

// SignPSS : Sign message
func SignPSS(privateKey *rsa.PrivateKey, newhash crypto.Hash, hashed []byte, pssOptions *rsa.PSSOptions) ([]byte, error) {

	signature, err := rsa.SignPSS(rand.Reader, privateKey, newhash, hashed, pssOptions)

	if err != nil {
		fmt.Println(err)
		return signature, nil
	}

	return signature, nil
}

// VerifyPSS : Verify Signature
func VerifyPSS(publicKey *rsa.PublicKey, newhash crypto.Hash, hashed []byte, signature []byte, pssOptions *rsa.PSSOptions) bool {

	//Verify Signature
	err := rsa.VerifyPSS(publicKey, newhash, hashed, signature, pssOptions)

	if err != nil {
		fmt.Printf("Who are U? Verify Signature failed: %v\n", err)
		return false
	} else {
		// fmt.Println("Verify Signature successful")
		return true
	}

}

// GetServerPublicKey : get server public key
func GetServerPublicKey() *rsa.PublicKey {
	pubStr, err := ioutil.ReadFile("keystore/clientpub")
	if err != nil {
		panic(err)
	}

	pub, err := ParseRsaPublicKeyFromPemStr(string(pubStr))
	if err != nil {
		panic(err)
	}

	return pub
}

// GetServerPrivateKey : get server private key
func GetServerPrivateKey() *rsa.PrivateKey {
	privStr, err := ioutil.ReadFile("keystore/clientpriv")
	if err != nil {
		panic(err)
	}

	priv, err := ParseRsaPrivateKeyFromPemStr(string(privStr))
	if err != nil {
		panic(err)
	}

	return priv
}

// GetClientPublicKey : get client public key
func GetClientPublicKey(publicfile string) *rsa.PublicKey {
	pubStr, err := ioutil.ReadFile("keystore/" + publicfile)
	if err != nil {
		panic(err)
	}

	pub, err := ParseRsaPublicKeyFromPemStr(string(pubStr))
	if err != nil {
		panic(err)
	}

	return pub
}

// GetClientPrivateKey : get client private key
func GetClientPrivateKey(privatefile string) *rsa.PrivateKey {
	privStr, err := ioutil.ReadFile("keystore/" + privatefile)
	if err != nil {
		panic(err)
	}

	priv, err := ParseRsaPrivateKeyFromPemStr(string(privStr))
	if err != nil {
		panic(err)
	}

	return priv
}
