// Package decode decrypts captured MIoT responses offline.
package decode

import (
	"bytes"
	"compress/gzip"
	"crypto/rc4"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Yonsm/misgo/miio/sign"
)

// Decode decrypts a captured MIoT response using its ssecurity and nonce and
// returns its JSON payload. If unzip is set, gzip-compressed payloads are unzipped.
func Decode(ssecurity, encodedNonce, data string, unzip bool) (any, error) {
	key, err := sign.Nonce(ssecurity, encodedNonce)
	if err != nil {
		return nil, err
	}
	body, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("invalid MIoT ciphertext: %w", err)
	}
	cipher, err := rc4.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	var drop [1024]byte
	cipher.XORKeyStream(drop[:], drop[:])
	cipher.XORKeyStream(body, body)

	if unzip && len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b {
		r, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("invalid MIoT gzip payload: %w", err)
		}
		defer r.Close()
		const maxPayload = 32 << 20
		body, err = io.ReadAll(io.LimitReader(r, maxPayload+1))
		if err != nil {
			return nil, fmt.Errorf("invalid MIoT gzip payload: %w", err)
		}
		if len(body) > maxPayload {
			return nil, errors.New("MIoT gzip payload exceeds size limit")
		}
	}
	if !json.Valid(body) {
		return nil, errors.New("invalid MIoT decoded payload: expected a single JSON value")
	}
	var result any
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	if err := d.Decode(&result); err != nil {
		return nil, fmt.Errorf("invalid MIoT decoded payload: %w", err)
	}
	return result, nil
}
