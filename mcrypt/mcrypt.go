package mcrypt

import (
	"encoding/base64"
	"fmt"
	mathRand "math/rand"
	"time"

	"github.com/elliotchance/phpserialize"
	mcrypt "github.com/mfpierre/go-mcrypt"
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
