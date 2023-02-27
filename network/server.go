package network

import (
	"encoding/hex"

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
		return
	}
	c.JSON(200, gin.H{"priv": hex.EncodeToString(priv.D.Bytes()), "pub": hex.EncodeToString(pub.X.Bytes())})
}

func (s *Server) encrypt(c *gin.Context) {
	var msg EncryptMsg
	err := c.BindJSON(&msg)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	cipherText, err := sm2.Encrypt(msg.pub, []byte(msg.PlainText), sm2.C1C3C2)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"cipher_text": hex.EncodeToString(cipherText)})
}

func (s *Server) decrypt(c *gin.Context) {
	var msg DecryptMsg
	err := c.BindJSON(&msg)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	plainText, err := sm2.Decrypt(msg.priv, []byte(msg.CipherText), sm2.C1C3C2)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"plain_text": hex.EncodeToString(plainText)})
}

func (s *Server) sign(c *gin.Context) {
	var msg SignMsg
	err := c.BindJSON(&msg)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	signResult, err := sm2.Sign(msg.priv, nil, []byte(msg.PlainText))
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"sign_result": hex.EncodeToString(signResult)})
}

func (s *Server) verify(c *gin.Context) {
	var msg VerifyMsg
	err := c.BindJSON(&msg)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	verifyResult := sm2.Verify(msg.pub, nil, []byte(msg.PlainText), []byte(msg.SignResult))
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
