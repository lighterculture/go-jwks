package jwks

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var httpClient *http.Client

func init() {
	httpClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// Allow for insecure clients (poc/testing purposes)
				InsecureSkipVerify: strings.ToLower(os.Getenv("HTTP_CLIENT_INSECURE")) == "true",
			},
		},
	}
}

// JWKS is JSON Web Key Set
type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

// JSONWebKey is the data model for a JSON Web Key
type JSONWebKey struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

// NewClient returns a Client which is used to fetch keys from a supplied endpoint.
// It will attempt to cache the keys returned before returning. If an error
// occurs, it will return an error (with the instantiated Client).
func NewClient(endpoint string) (*Client, error) {
	c := &Client{
		endpoint: endpoint,
		keys: cache{
			kv:  make(map[string]interface{}),
			mtx: &sync.RWMutex{},
		},
	}

	return c, c.updateCache()
}

// Client fetchs and maintains a cache of keys from a public endpoint.
type Client struct {
	endpoint string
	keys     cache
}

// GetKey returns a key for a given key id.
// It first looks in the Client's cache and if it can not find a key it
// will attempt fetch the key from the endpoint directly.
func (c *Client) GetKey(kid string) (interface{}, error) {
	key, ok := c.keys.get(kid)
	if !ok {
		if err := c.updateCache(); err != nil {
			return nil, err
		}
	}

	key, ok = c.keys.get(kid)
	if !ok {
		return nil, errors.New("unrecognized key id")
	}

	return key, nil
}

func (c *Client) GetKeyAsPEM(kid string) ([]byte, error) {
	key, err := c.GetKey(kid)
	if err != nil {
		return nil, err
	}
	pem, err := getPEM(key.(JSONWebKey))
	if err != nil {
		return nil, err
	}
	return pem, nil
}

func (c *Client) updateCache() error {
	ks, err := fetchJWKs(c.endpoint)
	if err != nil {
		return err
	}

	for _, k := range ks {
		c.keys.put(k.Kid, k)
	}

	return nil
}

func getPEM(jwk JSONWebKey) ([]byte, error) {
	if len(jwk.X5c) < 1 {
		return nil, errors.New("No certificate found")
	}
	cert := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", jwk.X5c[0])
	return []byte(cert), nil
}

func fetchJWKs(origin string) ([]JSONWebKey, error) {
	var ks JSONWebKeySet

	resp, err := httpClient.Get(origin)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&ks); err != nil {
		return nil, err
	}

	return ks.Keys, nil
}

type cache struct {
	kv  map[string]interface{}
	mtx *sync.RWMutex
}

func (c *cache) get(k string) (interface{}, bool) {
	c.mtx.RLock()
	v, ok := c.kv[k]
	c.mtx.RUnlock()
	return v, ok
}

func (c *cache) put(k string, v interface{}) {
	c.mtx.Lock()
	c.kv[k] = v
	c.mtx.Unlock()
}
