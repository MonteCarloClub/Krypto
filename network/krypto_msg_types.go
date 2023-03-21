package network

type EncryptMsg struct {
	PlainText string `json:"plain_text"`
	Pub       []byte `json:"pub"`
}

type DecryptMsg struct {
	CipherText string `json:"cipher_text"`
	Priv       []byte `json:"priv"`
}

type SignMsg struct {
	PlainText string `json:"plain_text"`
	Priv      []byte `json:"priv"`
}

type VerifyMsg struct {
	PlainText  string `json:"plain_text"`
	SignResult string `json:"sign_result"`
	Pub        []byte `json:"pub"`
}

type HashMsg struct {
	PlainText string `json:"plain_text"`
}
