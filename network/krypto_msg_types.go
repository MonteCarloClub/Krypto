package network

type EncryptMsg struct {
	PlainText string `json:"plain_text"`
	Pub       string `json:"pub"`
}

type DecryptMsg struct {
	CipherText string `json:"cipher_text"`
	Priv       string `json:"priv"`
}

type SignMsg struct {
	PlainText string `json:"plain_text"`
	Priv      string `json:"priv"`
}

type VerifyMsg struct {
	PlainText  string `json:"plain_text"`
	SignResult string `json:"sign_result"`
	Pub        string `json:"pub"`
}

type HashMsg struct {
	PlainText string `json:"plain_text"`
}
