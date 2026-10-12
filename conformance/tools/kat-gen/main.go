// One-off generator: HPKE-7 blobs from an implementation independent of
// rust_jwk_duo (Cloudflare CIRCL). Output: conformance/jwk_duo/hpke_open.json.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/cloudflare/circl/hpke"
)

var b64u = base64.RawURLEncoding
var b64 = base64.StdEncoding

func jwk(x, y, d []byte, alg, use string) map[string]string {
	canon := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, b64u.EncodeToString(x), b64u.EncodeToString(y))
	sum := sha256.Sum256([]byte(canon))
	return map[string]string{"kty": "EC", "crv": "P-256", "x": b64u.EncodeToString(x), "y": b64u.EncodeToString(y), "d": b64u.EncodeToString(d), "kid": b64u.EncodeToString(sum[:]), "alg": alg, "use": use}
}

func pad32(b []byte) []byte { out := make([]byte, 32); copy(out[32-len(b):], b); return out }

func main() {
	kem := hpke.KEM_P256_HKDF_SHA256
	suite := hpke.NewSuite(kem, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
	pk, sk, err := kem.Scheme().GenerateKeyPair()
	must(err)
	pkb, _ := pk.MarshalBinary() // 65-byte SEC1 uncompressed
	skb, _ := sk.MarshalBinary() // 32-byte scalar
	sig, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	set := map[string]any{"keys": []map[string]string{
		jwk(pad32(sig.X.Bytes()), pad32(sig.Y.Bytes()), pad32(sig.D.Bytes()), "ES256", "sig"),
		jwk(pkb[1:33], pkb[33:65], skb, "HPKE-7", "enc"),
	}}
	setJSON, _ := json.Marshal(set)
	type in struct {
		JwkSet string `json:"jwk_set"`
		Blob   string `json:"blob_b64"`
		Info   string `json:"info_b64"`
		Aad    string `json:"aad_b64"`
	}
	type kase struct {
		ID     string            `json:"id"`
		Input  in                `json:"input"`
		Expect map[string]string `json:"expect"`
	}
	var cases []kase
	for _, c := range []struct{ id, info, aad, pt string }{{"empty", "", "", ""}, {"ctx", "app-ctx", "row-42", "hello jwk_duo"}} {
		info := append([]byte("rust_jwk_duo/hpke/v1\x00"), []byte(c.info)...)
		snd, err := suite.NewSender(pk, info)
		must(err)
		enc, sealer, err := snd.Setup(rand.Reader)
		must(err)
		ct, err := sealer.Seal([]byte(c.pt), []byte(c.aad))
		must(err)
		blob := append(append([]byte{0x01}, enc...), ct...)
		cases = append(cases, kase{c.id, in{string(setJSON), b64.EncodeToString(blob), b64.EncodeToString([]byte(c.info)), b64.EncodeToString([]byte(c.aad))}, map[string]string{"ok": b64.EncodeToString([]byte(c.pt))}})
	}
	out := map[string]any{"format_version": 1, "op": "crypto.decrypt", "generator": "cloudflare/circl hpke", "cases": cases}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	must(enc.Encode(out))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
