package ratchet

import "metachat/internal/crypto"

type Ratchet struct {
	RootKey   []byte
	ChainKey  []byte
	DHPriv    []byte
	DHPub     []byte
	RemotePub []byte
}

func NewRatchet(sharedSecret, remotePub []byte) *Ratchet {
	priv, pub := crypto.GenerateKeyPair()
	root := crypto.HKDF(sharedSecret, "root")
	chain := crypto.HKDF(root, "chain")
	return &Ratchet{
		RootKey:   root,
		ChainKey:  chain,
		DHPriv:    priv,
		DHPub:     pub,
		RemotePub: remotePub,
	}
}

func (r *Ratchet) RatchetStep() {
	dhOut := crypto.DH(r.DHPriv, r.RemotePub)
	r.RootKey = crypto.HKDF(dhOut, "root")
	r.ChainKey = crypto.HKDF(r.RootKey, "chain")
	r.DHPriv, r.DHPub = crypto.GenerateKeyPair()
}

func (r *Ratchet) NextMessageKey() []byte {
	r.ChainKey = crypto.HKDF(r.ChainKey, "chain-step")
	return crypto.HKDF(r.ChainKey, "msg")
}
