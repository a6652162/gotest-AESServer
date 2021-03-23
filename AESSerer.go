/*
VirtualMoon
描述 :  golang
通过HTTP服务接口
AES/ECB/PKCS5  加密解密
16位密钥 + ; + 处理字符
date : 2020-05-26
*/

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

func main() {

	//固定取前16位在密码
	// key := []byte("1234567890123456")
	// mw := []byte("ad0dd1f5665d150edaaf52e2d41f69885877e81f5f06a37c592ea8bf5717c0f03681d5070138921b270a677079e5ea0848b210be2abd46a59c643be108ed36fe5e3722406a37fdeaa135435cadb983191ce41581ddb7a37a88d89ea7df9ba3e4914e6fe718415e1a64874f7d21184a2417362096046312856e1f5438d9c52a03da7d33fe5c10b86685727f3f2d7efe976c44b29bf9eb6d771ee51d24ea601ac1a373716b67fe44d581a0d11ee8a244669a387559c15093a0126bd7e3aac60264f0b3289aa7cd4d88f46d7b73a9db9f6cb310335dbdc07c18064f2718d16d4908e1040f2d38f23ecdbab17897b23d46f0a4318c54e03bd044b47a6daa5e63a016eb796677bb05d3633745731b7d9f4e137e8e74fff2482cfc3ca9b917668188c1700176b124d3db20c173f32ffc12fc4ef03312fb95636784d1ddd331964962269ce35668c38748479e582edd2277cd3cc9679f5582753e7328a971201a3852bc6e68331569fe0397e8e7dd1100acb783056e0fe296813d407d4965a7b7e2291b2b6a26071d9647881cc1532b99e5d06e900d7ad84979116ea9e2c0672537a9c1")
	// src, _ := hex.DecodeString(string(mw))

	// resvalue := AesDecrypt(src, key)
	// fmt.Println(string(resvalue))

	//监听协议
	http.HandleFunc("/", HelloWorldHandler)
	http.HandleFunc("/AesEncrypt", AesEncryptHandler)
	http.HandleFunc("/AesDecrypt", AesDecryptHandler)
	fmt.Println("Port:", 6999)
	//监听服务
	err := http.ListenAndServe("0.0.0.0:6999", nil)

	if err != nil {
		fmt.Println("服务器错误")
	}
}

//加密接口
func AesEncryptHandler(response http.ResponseWriter, request *http.Request) {
	defer func() {
		//恢复程序的控制权
		err := recover()
		if err != nil {
			fmt.Println("加密异常，", err)
			fmt.Fprintf(response, "Error")
		}
	}()
	buff, _ := ioutil.ReadAll(request.Body)
	//fmt.Println("原文：", string(buff))
	if len(buff) < 18 {
		fmt.Fprintf(response, "Error")
		return
	}
	//固定取前16位在密码
	key := string(buff[0:16])
	mw := buff[17:len(buff)]
	crypted := AesEncrypt(string(mw), key)
	//fmt.Println("加密后：", hex.EncodeToString(crypted))
	response.Write([]byte(strings.ToUpper(hex.EncodeToString(crypted))))
	// fmt.Fprintf(response, strings.ToUpper(hex.EncodeToString(crypted)))
}

//解密接口
func AesDecryptHandler(response http.ResponseWriter, request *http.Request) {
	defer func() {
		//恢复程序的控制权
		err := recover()
		if err != nil {
			fmt.Println("解密异常，", err)
			fmt.Fprintf(response, "Error")
		}
	}()

	buff, _ := ioutil.ReadAll(request.Body)
	//fmt.Println("密文：", string(buff))
	if len(buff) < 18 {
		fmt.Fprintf(response, "Error")
		return
	}
	//固定取前16位在密码
	key := buff[0:16]
	mw := buff[17:len(buff)]
	src, err := hex.DecodeString(string(mw))
	if err != nil {
		fmt.Fprintf(response, err.Error())
		return
	}
	resvalue := AesDecrypt(src, key)
	//fmt.Println("解密后：", string(resvalue))
	response.Write(resvalue)
}

func HelloWorldHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("r.Method = ", r.Method)
	fmt.Println("r.URL = ", r.URL)
	fmt.Println("r.Header = ", r.Header)
	fmt.Println("r.Body = ", r.Body)
	fmt.Fprintf(w, "HelloWorld!")
}

func Base64URLDecode(data string) ([]byte, error) {
	var missing = (4 - len(data)%4) % 4
	data += strings.Repeat("=", missing)
	res, err := base64.URLEncoding.DecodeString(data)
	fmt.Println("  decodebase64urlsafe is :", string(res), err)
	return base64.URLEncoding.DecodeString(data)
}

func Base64UrlSafeEncode(source []byte) string {
	// Base64 Url Safe is the same as Base64 but does not contain '/' and '+' (replaced by '_' and '-') and trailing '=' are removed.
	bytearr := base64.StdEncoding.EncodeToString(source)
	safeurl := strings.Replace(string(bytearr), "/", "_", -1)
	safeurl = strings.Replace(safeurl, "+", "-", -1)
	safeurl = strings.Replace(safeurl, "=", "", -1)
	return safeurl
}

func AesDecrypt(crypted, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("err is:", err)
	}
	blockMode := NewECBDecrypter(block)
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	// fmt.Println("source is :", origData, string(origData))
	return origData
}

func AesEncrypt(src, key string) []byte {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		fmt.Println("key error1", err)
	}
	if src == "" {
		fmt.Println("plain content empty")
	}
	ecb := NewECBEncrypter(block)
	content := []byte(src)
	content = PKCS5Padding(content, block.BlockSize())
	crypted := make([]byte, len(content))
	ecb.CryptBlocks(crypted, content)
	// // 普通base64编码加密 区别于urlsafe base64
	// fmt.Println("base64 result:", base64.StdEncoding.EncodeToString(crypted))

	// fmt.Println("base64UrlSafe result:", Base64UrlSafeEncode(crypted))
	return crypted
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncrypter ecb

// NewECBEncrypter returns a BlockMode which encrypts in electronic code book
// mode, using the given Block.
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}
func (x *ecbEncrypter) BlockSize() int { return x.blockSize }
func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

type ecbDecrypter ecb

// NewECBDecrypter returns a BlockMode which decrypts in electronic code book
// mode, using the given Block.
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}
func (x *ecbDecrypter) BlockSize() int { return x.blockSize }
func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
