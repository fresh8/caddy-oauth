package oauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
)

//helpers for securely encrypting / decrypting cookies
//uses an encrypt-then-sign scheme with AES-CFB and SHA256

type encryptor struct {
	hmacKey []byte
	aes     cipher.Block
}

func newEncryptor(secret string) *encryptor {
	//turn secret into two keys by hashing twice
	hkey := sha256.Sum256([]byte(secret))
	akey := sha256.Sum256([]byte(hkey[:]))
	blok, _ := aes.NewCipher(akey[:])
	return &encryptor{hkey[:], blok}
}

func (e *encryptor) encrypt(plaintext []byte) string {
	//encrypt then sign
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return ""
	}
	stream := cipher.NewCFBEncrypter(e.aes, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	hash := e.hash(ciphertext)
	e.hash(ciphertext)
	return base64.StdEncoding.EncodeToString(append(hash, ciphertext...))
}

//calculate and return the sha256 hmac of the given data
func (e *encryptor) hash(ciphertext []byte) []byte {
	h := hmac.New(sha256.New, e.hmacKey)
	_, err := h.Write(ciphertext)
	if err != nil {
		return []byte{}
	}
	m := h.Sum(nil)
	return m
}

func (e *encryptor) decrypt(cookieData string) string {
	ciphertext, err := base64.StdEncoding.DecodeString(cookieData)
	if err != nil {
		return ""
	}
	if len(ciphertext) < sha256.Size+aes.BlockSize { //at least room for iv and hmac
		return ""
	}
	//first validate hmac
	msgMac := ciphertext[:sha256.Size]
	ciphertext = ciphertext[sha256.Size:]
	actualMac := e.hash(ciphertext)
	if !hmac.Equal(msgMac, actualMac) {
		return ""
	}
	// pull out iv and decrypt
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(e.aes, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return string(ciphertext)
}
