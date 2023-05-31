package security

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
)

// Meaningful errors.
var (
	ErrBadSignature = errors.New("bad signature")
)

// Signature is a cryptographic signature of some piece of data.
type Signature []byte

func (s Signature) verify(k crypto.PubKey, data []byte) error {
	ok, err := k.Verify(data, s)
	if err != nil {
		return fmt.Errorf("%s: %w", err, ErrBadSignature)
	}

	if !ok {
		return ErrBadSignature
	}

	return nil
}

type Principal []byte

// String encodes Principal as a string, using base58btc encoding as defined in DID Key spec.
func (p Principal) String() string {
	if len(p) == 0 {
		return ""
	}

	s, err := multibase.Encode(multibase.Base58BTC, p)
	if err != nil {
		panic(err)
	}
	return s
}

// Explode splits the principal into it's multicodec and raw key bytes.
func (p Principal) Explode() (multicodec.Code, []byte) {
	code, n := binary.Uvarint(p)
	return multicodec.Code(code), p[n:]
}

// PrincipalFromPubKey converts a Libp2p public key into Principal.
func PrincipalFromPubKey(k crypto.PubKey) (Principal, error) {
	codec, ok := pubKeyCodecs[int(k.Type())]
	if !ok {
		return nil, fmt.Errorf("Invalid principal key type")
	}

	raw, err := k.Raw()
	if err != nil {
		return nil, err
	}

	prefix, ok := pubKeyCodecBytes[codec]
	if !ok {
		return nil, fmt.Errorf("no prefix for codec %s", codec.String())
	}

	out := make([]byte, 0, len(raw)+len(prefix))
	out = append(out, prefix...)
	out = append(out, raw...)

	return Principal(out), nil
}

// Verify implements Verifier.
func (p Principal) Verify(data []byte, sig Signature) error {
	code, key := p.Explode()
	if code != multicodec.Ed25519Pub {
		panic("BUG: unsupported key type")
	}

	pk, err := crypto.UnmarshalEd25519PublicKey(key)
	if err != nil {
		return err
	}

	return sig.verify(pk, data)
}

var pubKeyCodecs = map[int]multicodec.Code{
	crypto.Ed25519:   multicodec.Ed25519Pub,
	crypto.Secp256k1: multicodec.Secp256k1Pub,
}

var pubKeyCodecBytes = map[multicodec.Code][]byte{
	multicodec.Ed25519Pub:   binary.AppendUvarint(nil, uint64(multicodec.Ed25519Pub)),
	multicodec.Secp256k1Pub: binary.AppendUvarint(nil, uint64(multicodec.Secp256k1Pub)),
}

// DecodePrincipal decodes the principal from its string representation.
func DecodePrincipal(s string) (Principal, error) {
	enc, data, err := multibase.Decode(s)
	if err != nil {
		return nil, err
	}

	if enc != multibase.Base58BTC {
		return nil, fmt.Errorf("unsupported principal multibase: %s", multicodec.Code(enc).String())
	}

	return Principal(data), nil
}
