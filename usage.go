package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/MonteCarloClub/Krypto/sm2"
	"github.com/MonteCarloClub/Krypto/sm3"
)

func main() {
	// 椭圆曲线参数
	curve := sm2.GetSm2P256V1()
	fmt.Printf("P:%s\n", curve.Params().P.Text(16))
	fmt.Printf("B:%s\n", curve.Params().B.Text(16))
	fmt.Printf("N:%s\n", curve.Params().N.Text(16))
	fmt.Printf("Gx:%s\n", curve.Params().Gx.Text(16))
	fmt.Printf("Gy:%s\n", curve.Params().Gy.Text(16))

	// 生成公私钥
	priv, pub, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("priv:%s\n", priv.D.Text(16))
	fmt.Printf("x:%s\n", pub.X.Text(16))
	fmt.Printf("y:%s\n", pub.Y.Text(16))

	if !curve.IsOnCurve(pub.X, pub.Y) {
		fmt.Println("x,y is not on Curve")
		return
	}
	fmt.Println("x,y is on sm2 Curve")

	// 加解密明文
	src := []byte{3, 1, 4, 1, 9, 2, 6, 5, 3}
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	cipherText, err := sm2.Encrypt(pub, src, sm2.C1C3C2)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("cipher text:%s\n", hex.EncodeToString(cipherText))

	plainText, err := sm2.Decrypt(priv, cipherText, sm2.C1C3C2)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("plain text:%s\n", hex.EncodeToString(plainText))

	if !bytes.Equal(plainText, src) {
		fmt.Println("decrypt failed")
		return
	}
	fmt.Println("decrypt Succeeded")

	// 签名与验签
	inBytes, _ := hex.DecodeString("314192653")
	sign, err := sm2.Sign(priv, nil, inBytes)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("sign:%s\n", hex.EncodeToString(sign))
	result := sm2.Verify(pub, nil, inBytes, sign)
	if !result {
		fmt.Println("verify failed")
		return
	}
	fmt.Println("verify Succeeded")

	// sm3
	hash := sm3.Sum(src)
	hashHex := hex.EncodeToString(hash[:])
	fmt.Printf("sm3 hash:%s\n", hashHex)
}
