package main

import (
	"crypto/aes"
	"crypto/cipher"
	cryptoRand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mathRand "math/rand"
	"time"

	"github.com/elliotchance/phpserialize"
	"github.com/mergermarket/go-pkcs7"
	mcrypt "github.com/mfpierre/go-mcrypt"
	"github.com/syyongx/php2go"
	utils "github.com/syyongx/php2go"
)

const (
	cipherKey     = "here is a random key of 32 bytes"
	text          = "1840400075998"
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func GenerateToken() string {
	key := utils.Md5(cipherKey)
	data := fmt.Sprintf("%s", phpserialize.MarshalString(token()))
	iv := utils.Md5(key)

	encrypted, _ := mcrypt.Encrypt([]byte(key), []byte(iv), []byte(data), "rijndael-256", "cbc")
	return utils.Strtr(base64.StdEncoding.EncodeToString(encrypted), "+/=", "-_,")
}

func token() string {
	key := utils.Md5(text)
	data := fmt.Sprintf("%s", phpserialize.MarshalString(randomString()))
	iv := utils.Md5(key)

	encrypted, _ := mcrypt.Encrypt([]byte(key), []byte(iv), []byte(data), "rijndael-256", "cbc")
	return utils.Strtr(base64.StdEncoding.EncodeToString(encrypted), "+/=", "-_,")
}

func randomString() string {
	val, _ := utils.Bin2hex(opensslRandomPseudoBytes(16))
	return utils.Md5(fmt.Sprintf("%s%s", val, utils.Uniqid("")))
}

func opensslRandomPseudoBytes(n int) string {
	src := mathRand.NewSource(time.Now().UnixNano())
	b := make([]byte, n)

	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; remain-- {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits

	}

	return string(b)
}

func main() {
	key := utils.Md5(text)
	data := fmt.Sprintf("%s", phpserialize.MarshalString(randomString()))
	iv := utils.Md5(key)

	encrypt, err := Encrypt(
		[]byte(key),
		[]byte(data),
		[]byte(iv),
	)
	if err != nil {
		return
	}

	encrypt = php2go.Strtr(
		base64.StdEncoding.EncodeToString([]byte(encrypt)),
		"+/=",
		"-_,",
	)
}

// Encrypt encrypts plain text string into cipher text string
func Encrypt(key, data, iv []byte) (string, error) {
	fmt.Printf("key: %s\n", key)
	fmt.Printf("data: %s\n", data)
	fmt.Printf("iv: %s\n", iv)
	fmt.Printf("token: %s", token())
	plainText, err := pkcs7.Pad(data, aes.BlockSize)
	if err != nil {
		return "", fmt.Errorf(`plainText: "%s" has error`, plainText)
	}

	if len(plainText)%aes.BlockSize != 0 {
		err := fmt.Errorf(`plainText: "%s" has the wrong block size`, plainText)
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv = cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(cryptoRand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], plainText)

	return fmt.Sprintf("%x", cipherText), nil
}

// Decrypt decrypts cipher text string into plain text string
func Decrypt(encrypted string) (string, error) {
	key := []byte(cipherKey)
	cipherText, _ := hex.DecodeString(encrypted)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(cipherText) < aes.BlockSize {
		return "", errors.New("error: cipher text too short")
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	if len(cipherText)%aes.BlockSize != 0 {
		return "", errors.New("error: cipher text is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherText, cipherText)
	cipherText, err = pkcs7.Unpad(cipherText, aes.BlockSize)
	if err != nil {
		return "", errors.New("error: cannot unpad")
	}

	return fmt.Sprintf("%s", cipherText), nil
}
