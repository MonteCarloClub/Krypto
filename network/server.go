package network

import (
	"crypto/rand"
	"fmt"

	"github.com/MonteCarloClub/Krypto/sm2"
	"github.com/MonteCarloClub/Krypto/sm3"
	"github.com/gin-gonic/gin"
)

// Server is a server for Krypto
type Server struct {
	addr string
}

// NewServer creates a new server
func NewServer(addr string) *Server {
	return &Server{addr: addr}
}

// Start starts the server
func (s *Server) Start() {
	r := gin.Default()
	r.POST("/keygen", s.generateKey)
	r.POST("/encrypt", s.encrypt)
	r.POST("/decrypt", s.decrypt)
	r.POST("/sign", s.sign)
	r.POST("/verify", s.verify)
	r.POST("/hash", s.hash)
	r.Run(s.addr)
}

func (s *Server) generateKey(c *gin.Context) {
	priv, pub, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
	}
	c.JSON(200, gin.H{"priv": priv.GetRawBytes(), "pub": pub.GetRawBytes()})
}

func (s *Server) encrypt(c *gin.Context) {
	var msg EncryptMsg
	err := c.BindJSON(&msg)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	pubKey, err := sm2.RawBytesToPublicKey([]byte(msg.Pub))
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	cipherText, err := sm2.Encrypt(pubKey, []byte(msg.PlainText), sm2.C1C3C2)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"cipher_text": cipherText})
}

func (s *Server) decrypt(c *gin.Context) {
	var msg DecryptMsg
	err := c.BindJSON(&msg)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	privKey, err := sm2.RawBytesToPrivateKey([]byte(msg.Priv))
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	plainText, err := sm2.Decrypt(privKey, []byte(msg.CipherText), sm2.C1C3C2)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"plain_text": plainText})
}

func (s *Server) sign(c *gin.Context) {
	var msg SignMsg
	err := c.BindJSON(&msg)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	privKey, err := sm2.RawBytesToPrivateKey([]byte(msg.Priv))
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	signResult, err := sm2.Sign(privKey, nil, []byte(msg.PlainText))
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"sign_result": signResult})
}

func (s *Server) verify(c *gin.Context) {
	var msg VerifyMsg
	err := c.BindJSON(&msg)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	pubKey, err := sm2.RawBytesToPublicKey([]byte(msg.Pub))
	fmt.Println(msg.Pub)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	verifyResult := sm2.Verify(pubKey, nil, []byte(msg.PlainText), []byte(msg.SignResult))
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"verify_result": verifyResult})
}

func (s *Server) hash(c *gin.Context) {
	var msg HashMsg
	err := c.BindJSON(&msg)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	hashResult := sm3.Sum([]byte(msg.PlainText))
	c.JSON(200, gin.H{"hash_result": hashResult})
}
