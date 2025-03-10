package security

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/libp2p/go-libp2p/core/crypto"
)

const LEGACY_LOGIN_MESSAGE = "sign in into mintter lndhub"

func SignatureMiddleware(loginMessage string) echo.MiddlewareFunc {
	config := middleware.DefaultKeyAuthConfig
	config.ErrorHandler = func(err error, c echo.Context) error {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusUnauthorized, echo.Map{
			"error":   true,
			"code":    -1,
			"message": "bad signature authentication: " + err.Error(),
		})
	}

	config.Validator = func(pubKeyStr string, c echo.Context) (bool, error) {
		return validateSignature(pubKeyStr, loginMessage, c)
	}
	config.Skipper = checkSkip
	return middleware.KeyAuthWithConfig(config)
}

func checkSkip(c echo.Context) bool {
	login, err := readFromBody(&c.Request().Body, "login")
	if err != nil {
		c.Logger().Debugf("could not read body %v", err)
		return false // so it fails downstream
	}
	var actualLogin = login.(string)

	_, err = DecodePrincipal(actualLogin)
	if err != nil {
		c.Logger().Debugf("login %s not a cid", actualLogin)
		return true
	}

	return false
}

func validateSignature(pubKeyStr, loginMessage string, c echo.Context) (bool, error) {
	// check proper headers
	v, ok := c.Request().Header[echo.HeaderAuthorization]
	if !ok || len(v) != 1 || !strings.Contains(strings.ToLower(v[0]),
		strings.ToLower(middleware.DefaultKeyAuthConfig.AuthScheme)) ||
		len(v[0]) <= len(middleware.DefaultKeyAuthConfig.AuthScheme+"  ") {
		return false, fmt.Errorf("wrong or absent signature auth format")
	}

	// check proper body
	pass, err := readFromBody(&c.Request().Body, "password")
	if err != nil {
		return false, fmt.Errorf("could not read body %v", err)
	}
	var password = pass.(string)

	login, err := readFromBody(&c.Request().Body, "login")
	if err != nil {
		return false, fmt.Errorf("could not read body %v", err)
	}
	var actualLogin = login.(string)

	// check pubkey leads to login
	pub, err := hex.DecodeString(pubKeyStr)
	if err != nil {
		return false, fmt.Errorf("could not decode provided public key [%s] %v", pubKeyStr, err)
	}

	pubKey, err := crypto.UnmarshalEd25519PublicKey(pub)
	if err != nil {
		return false, fmt.Errorf("unable to unmarshal pubkey %v", err)
	}

	expectedLogin, err := PrincipalFromPubKey(pubKey)
	if err != nil {
		return false, fmt.Errorf("Unable to get Principal from pubkey")
	}

	if actualLogin != expectedLogin.String() {
		err = fmt.Errorf("expected login %s bug got login %s", expectedLogin.String(), actualLogin)
		return false, err
	}

	// check signature is valid
	signature, err := hex.DecodeString(password)
	if err != nil {
		return false, fmt.Errorf("Unable to unmarshal signature [%s]: %v", password, err)
	}

	sig_ok, err := pubKey.Verify([]byte(loginMessage), signature)
	if err != nil {
		return false, fmt.Errorf("Unable to verify signature")
	}
	if !sig_ok {
		//TODO(juligasa): remove this once the MTT migration is done.
		sig_ok, err = pubKey.Verify([]byte(LEGACY_LOGIN_MESSAGE), signature)
		if err != nil {
			return false, fmt.Errorf("Unable to verify old signature")
		}
		if !sig_ok {
			return false, fmt.Errorf("signature and pubKey don't match")
		}
	}

	return true, nil
}

func readFromBody(r *io.ReadCloser, key string) (interface{}, error) {
	authBody := make(map[string]interface{})
	body_data, err := ioutil.ReadAll(*r)

	defer func(reader *io.ReadCloser, data []byte) {
		*reader = io.NopCloser(bytes.NewBuffer(data))
	}(r, body_data)

	if err != nil {
		return nil, fmt.Errorf("Couldn't read body: %v", err)
	}

	err = json.Unmarshal(body_data, &authBody)
	if err != nil {
		return nil, fmt.Errorf("Couldn't decode body: %v", err)
	}
	value, ok := authBody[key]

	if !ok {
		return nil, fmt.Errorf("key %s not present in body", key)
	}
	return value, nil
}
