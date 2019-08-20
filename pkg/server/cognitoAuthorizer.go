package server

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

type CognitoAuthorizer struct {
	jwks JWK
}

func (c *CognitoAuthorizer) authorize(req *http.Request) bool {
	auth := req.Header.Get("Authorization")
	if len(auth) <= len("Bearer ") {
		return false
	}
	authToken := auth[len("Bearer "):len(auth)]

	token, err := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
		key := c.convertKey(c.jwks.Keys[1].E, c.jwks.Keys[1].N)
		return key, nil
	})

	if err != nil || !token.Valid {
		return false
	} else {
		//fmt.Printf("Claims: %+v\n", token.Claims)
		return true
	}
}

func (c *CognitoAuthorizer) convertKey(rawE, rawN string) *rsa.PublicKey {
	decodedE, err := base64.RawURLEncoding.DecodeString(rawE)
	if err != nil {
		panic(err)
	}
	if len(decodedE) < 4 {
		ndata := make([]byte, 4)
		copy(ndata[4-len(decodedE):], decodedE)
		decodedE = ndata
	}
	pubKey := &rsa.PublicKey{
		N: &big.Int{},
		E: int(binary.BigEndian.Uint32(decodedE[:])),
	}
	decodedN, err := base64.RawURLEncoding.DecodeString(rawN)
	if err != nil {
		panic(err)
	}
	pubKey.N.SetBytes(decodedN)
	return pubKey
}

//Factory method
func NewCognitoAuthorizer(region string, userpoolId string) *CognitoAuthorizer {
	jwkURL := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", region, region+"_"+userpoolId)
	jwk, err := retrieveJWK(jwkURL)
	if err != nil {
		log.Fatal(err)
	}

	return &CognitoAuthorizer{
		jwks: *jwk,
	}
}

func retrieveJWK(jwkURL string) (*JWK, error) {
	req, err := http.NewRequest("GET", jwkURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	jwk := new(JWK)
	err = json.Unmarshal(body, jwk)
	if err != nil {
		return nil, err
	}
	return jwk, nil
}

// JWK ...
type JWK struct {
	Keys []struct {
		Alg string `json:"alg"`
		E   string `json:"e"`
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		N   string `json:"n"`
	} `json:"keys"`
}
