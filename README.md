# Krypto

包含SM2加解密和签名算法、SM3密码杂凑算法，用于自主可控链

### SM2使用方法

#### 生成密钥

`priv, pub, err := sm2.GenerateKey(rand.Reader)`

`priv`为私钥，`pub`为公钥

#### 加密

`cipherText, err := sm2.Encrypt(pub, src, sm2.C1C3C2)`

`cipherText`为密文，`pub`为公钥，`src`为明文，第三个函数参数为密文编码格式

#### 解密

`plainText, err := sm2.Decrypt(priv, cipherText, sm2.C1C3C2)`

`plainText`为明文，`priv`为私钥，`cipherText`为密文，第三个函数参数为密文编码格式

#### 签名

`sign, err := sm2.Sign(priv, nil, inBytes)`

`sign`为签名内容，`priv`为私钥，第二个函数参数为ID，默认为1234567812345678，`inBytes`为签名对象

#### 验签

`result := sm2.Verify(pub, nil, inBytes, sign)`

`result`为验签结果，`pub`为私钥，第二个函数参数为ID，默认为1234567812345678，`inBytes`为验签对象内容部分，`sign`为验签对象签名部分

### SM3使用方法

`hash := sm3.Sum(src)`

`hash`为散列值，`src`为原文

