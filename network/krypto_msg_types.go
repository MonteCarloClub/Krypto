package network

type EncryptMsg struct {
	PlainText []byte `json:"plain_text"`
	Pub       []byte `json:"pub"`
}

type DecryptMsg struct {
	CipherText []byte `json:"cipher_text"`
	Priv       []byte `json:"priv"`
}

type SignMsg struct {
	PlainText []byte `json:"plain_text"`
	Priv      []byte `json:"priv"`
}

type VerifyMsg struct {
	PlainText  []byte `json:"plain_text"`
	SignResult []byte `json:"sign_result"`
	Pub        []byte `json:"pub"`
}

type HashMsg struct {
	PlainText []byte `json:"plain_text"`
}
