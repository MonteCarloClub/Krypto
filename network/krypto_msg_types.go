package network
import (
	"github.com/MonteCarloClub/Krypto/sm2"
)

type EncryptMsg struct {
	PlainText string `json:"plain_text"`
	pub *sm2.PublicKey `json:"pub"`
}

type DecryptMsg struct {
	CipherText string `json:"cipher_text"`
	priv *sm2.PrivateKey `json:"priv"`
}

type SignMsg struct {
	PlainText string `json:"plain_text"`
	priv *sm2.PrivateKey `json:"priv"`
}

type VerifyMsg struct {
	PlainText  string `json:"plain_text"`
	SignResult string `json:"sign_result"`
	pub *sm2.PublicKey `json:"pub"`
}

type HashMsg struct {
	PlainText string `json:"plain_text"`
}