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
	fmt.Printf("Request headers: %+v\n", req.Header)
	auth := req.Header.Get("Authorization")
	if len(auth) <= len("Bearer ") {
		fmt.Println("Failed to get Bearer token " + auth)
		return false
	}
	authToken := auth[len("Bearer "):len(auth)]
	E := "AQAB"
	//E := "AQAC"
	N := "u-_nfb3nv38zEs9FbkK8CGg5_hhK0DubPB_GEArv3hezDk0FwAzQ6dO1lkITtPOtzwaY-pitG16VttVvjKFYzPM7bq-r0ibNumAbEV90aa0t41DlhHTyt-5j3toQeaCYYJgSDYgsJOgMEyRM1UM3cgCWVQGk0sjgNFnvUaGdeKeUQpupXmyLJ6E5Q5Gjl7NJjGne67xyNElZpxh7AlIV0aKZJnC-Devz7KOLE5QPWV6QRFABtXcBGeUvAAVkq8Txjdj_rJLN2ftjOFpBgG67QcnV0CujqslphvjjyDuQ3E1EEsQIH5N49hzd5KsALUIg7t4keN3WnU0dt2tyUlFjYQ"
	// Parse takes the token string and a function for looking up the key. The latter is especially
	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
	// head of the token to identify which key to use, but the parsed token (head and claims) is provided
	// to the callback, providing flexibility.
	token, err := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
		key := c.convertKey(E, N)
		return key, nil
	})

	if token.Valid {
		//fmt.Println(token.Raw)
		fmt.Printf("Claims: %+v\n", token.Claims)
		fmt.Printf("Header: %+v\n", token.Header)
		//fmt.Println(token.Claims)
		return true
	} else {
		fmt.Printf("Claims: %+v\n", err)
		return false
	}
}

func (c *CognitoAuthorizer) convertKey(rawE, rawN string) *rsa.PublicKey {
	fmt.Println("+++++++++++++++++++++++++convertKey")
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
