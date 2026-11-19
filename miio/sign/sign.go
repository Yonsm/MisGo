// Package sign implements MiIO cloud request signing.
package sign

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"time"
)

// Nonce returns the request key for a base64-encoded service security value and nonce.
func Nonce(ssecurity, nonce string) ([sha256.Size]byte, error) {
	security, err := base64.StdEncoding.DecodeString(ssecurity)
	if err != nil || len(security) == 0 {
		return [sha256.Size]byte{}, errors.New("invalid MiIO ssecurity")
	}
	decoded, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil || len(decoded) == 0 {
		return [sha256.Size]byte{}, errors.New("invalid MiIO nonce")
	}
	return sha256.Sum256(append(security, decoded...)), nil
}

// EncodedNonce derives the base64-encoded request key from the service security value and nonce.
func EncodedNonce(ssecurity, encodedNonce string) (string, error) {
	key, err := Nonce(ssecurity, encodedNonce)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key[:]), nil
}

// Data signs a raw JSON string or a JSON-serializable value for a MiIO URI.
func Data(uri string, data any, ssecurity string) (url.Values, error) {
	payload, ok := data.(string)
	if !ok {
		b, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("encode MiIO request data: %w", err)
		}
		payload = string(b)
	}
	var n [12]byte
	if _, err := rand.Read(n[:8]); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(n[8:], uint32(time.Now().Unix()/60))
	enc := base64.StdEncoding
	encodedNonce := enc.EncodeToString(n[:])
	key, err := Nonce(ssecurity, encodedNonce)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key[:])
	io.WriteString(mac, uri+"&"+enc.EncodeToString(key[:])+"&"+encodedNonce+"&data="+payload)
	return url.Values{"_nonce": {encodedNonce}, "data": {payload}, "signature": {enc.EncodeToString(mac.Sum(nil))}}, nil
}
