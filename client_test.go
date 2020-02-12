package jwks

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

const keyId = "go-jwks-test"

func getJwksHandler(t *testing.T) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks, err := ioutil.ReadFile("./fixtures/jwks.json")
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(w, string(jwks))
	})
}

func getFixtureAsJWKS() (*JSONWebKeySet, error) {
	var ks JSONWebKeySet
	f, err := os.Open("./fixtures/jwks.json")
	defer f.Close()
	if err != nil {
		return nil, err
	}

	if err := json.NewDecoder(f).Decode(&ks); err != nil {
		return nil, err
	}

	return &ks, nil
}

func TestFetchJWKs(t *testing.T) {
	ts := httptest.NewServer(getJwksHandler(t))
	defer ts.Close()

	keys, err := fetchJWKs(ts.URL)

	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 1 {
		t.Fatalf("Expected one key, got %v", len(keys))
	}

	if keys[0].Kid != keyId {
		t.Fatalf("Expected key id %v, got %v", keyId, keys[0].Kid)
	}
}

func TestGetPEM(t *testing.T) {
	jwks, err := getFixtureAsJWKS()
	if err != nil {
		t.Fatal(err)
	}
	pem, err := getPEM(jwks.Keys[0])
	if err != nil {
		t.Fatal(err)
	}
	expected, err := ioutil.ReadFile("./fixtures/key.pem")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pem, expected) {
		t.Fatalf("Expected generated PEM file to match fixture")
	}
}

func TestNewClient(t *testing.T) {
	ts := httptest.NewServer(getJwksHandler(t))
	defer ts.Close()

	_, err := NewClient(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetKey(t *testing.T) {
	ts := httptest.NewServer(getJwksHandler(t))
	defer ts.Close()

	c, err := NewClient(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	key, err := c.GetKey(keyId)
	if err != nil {
		t.Fatal(err)
	}

	jwks, err := getFixtureAsJWKS()
	if err != nil {
		t.Fatal(err)
	}

	// keyJSON, err := key.(jose.JSONWebKey).MarshalJSON()
	// expectedJSON, err := jwks.Keys[0].MarshalJSON()
	var keyJSON, expectedJSON []byte
	keyJSON, err = json.Marshal(&key)
	if err != nil {
		t.Fatal(err)
	}
	expectedJSON, err = json.Marshal(&jwks.Keys[0])
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(keyJSON, expectedJSON) {
		t.Fatalf("Expected cached key and fixture key to be the same")
	}
}

func TestGetKeyAsPEM(t *testing.T) {
	ts := httptest.NewServer(getJwksHandler(t))
	defer ts.Close()

	c, err := NewClient(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	key, err := c.GetKeyAsPEM(keyId)
	if err != nil {
		t.Fatal(err)
	}

	expected, err := ioutil.ReadFile("./fixtures/key.pem")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(key, expected) {
		t.Fatalf("Expected cached key and fixture key to be the same")
	}
}
