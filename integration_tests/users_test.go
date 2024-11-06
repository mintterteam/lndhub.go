package integration_tests

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"math/rand"

	"github.com/libp2p/go-libp2p/core/crypto"

	v2controllers "github.com/getAlby/lndhub.go/controllers_v2"
	"github.com/getAlby/lndhub.go/lib"
	"github.com/getAlby/lndhub.go/lib/responses"
	"github.com/getAlby/lndhub.go/lib/security"
	"github.com/getAlby/lndhub.go/lib/service"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

var (
	PRIV_KEY = []byte{8, 1, 18, 64, 250, 126, 64, 211, 185, 52, 213, 138, 129, 240, 49, 215, 8, 0, 143, 232, 142, 33, 34, 171, 16, 219, 41, 128, 102, 115, 188, 59, 39, 71, 124, 184, 234, 207, 90, 7, 190, 245, 13, 28, 12, 234, 139, 238, 38, 154, 82, 54, 239, 185, 155, 12, 144, 51, 65, 143, 172, 48, 165, 199, 34, 254, 25, 96}
)

const (
	SIGNING_PHRASE = "sign in into lndhub for testing!"
)

type UsersTestSuite struct {
	TestSuite
	Service *service.LndhubService
}

func (suite *UsersTestSuite) SetupSuite() {
	svc, err := LndHubTestServiceInit(newDefaultMockLND())
	if err != nil {
		log.Fatalf("Error initializing test service: %v", err)
	}
	suite.Service = svc
	e := echo.New()

	e.HTTPErrorHandler = responses.HTTPErrorHandler
	e.Validator = &lib.CustomValidator{Validator: validator.New()}
	suite.echo = e
	suite.echo.POST("/v2/create", v2controllers.NewUsersController(suite.Service).CreateUser, security.SignatureMiddleware(SIGNING_PHRASE))
	suite.echo.GET("/v2/check", v2controllers.NewUsersController(suite.Service).CheckUsers)
}

func (suite *UsersTestSuite) TearDownTest() {
	err := clearTable(suite.Service, "users")
	if err != nil {
		fmt.Printf("Tear down test error %v\n", err.Error())
		return
	}
}

func (suite *UsersTestSuite) TestCreateAndChangeNickname() {
	e := echo.New()
	e.HTTPErrorHandler = responses.HTTPErrorHandler

	var buf bytes.Buffer
	e.Validator = &lib.CustomValidator{Validator: validator.New()}
	priv, err := crypto.UnmarshalPrivateKey(PRIV_KEY)
	assert.NoError(suite.T(), err)
	pub := priv.GetPublic().(*crypto.Ed25519PublicKey)
	pubBytes, _ := pub.Raw()
	messageSigned, err := priv.Sign([]byte(SIGNING_PHRASE))
	assert.NoError(suite.T(), err)

	pub_bytes, err := pub.Raw()
	assert.NoError(suite.T(), err)
	pubKey, err := crypto.UnmarshalEd25519PublicKey(pub_bytes)
	assert.NoError(suite.T(), err)
	principal, err := security.PrincipalFromPubKey(pubKey)
	assert.NoError(suite.T(), err)
	testLogin := principal.String()

	assert.NoError(suite.T(), json.NewEncoder(&buf).Encode(&ExpectedCreateUserRequestBody{
		Login:    testLogin,
		Password: hex.EncodeToString(messageSigned),
	}))
	req := httptest.NewRequest(http.MethodPost, "/v2/create", &buf)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", hex.EncodeToString(pubBytes)))
	rec := httptest.NewRecorder()
	suite.echo.ServeHTTP(rec, req)
	responseBody := ExpectedCreateUserRequestBody{}
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	assert.NoError(suite.T(), json.NewDecoder(rec.Body).Decode(&responseBody))
	assert.EqualValues(suite.T(), testLogin, responseBody.Login)
	assert.EqualValues(suite.T(), "", responseBody.Nickname)
	assert.EqualValues(suite.T(), hex.EncodeToString(messageSigned), responseBody.Password)
	user, err := suite.Service.FindUserByLoginOrNickname(context.Background(), testLogin)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), testLogin, user.Login)

	const newNickname = "newNickname"
	assert.NoError(suite.T(), json.NewEncoder(&buf).Encode(&ExpectedCreateUserRequestBody{
		Login:    testLogin,
		Password: hex.EncodeToString(messageSigned),
		Nickname: newNickname,
	}))
	req2 := httptest.NewRequest(http.MethodPost, "/v2/create", &buf)
	req2.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req2.Header.Add("Authorization", fmt.Sprintf("Bearer %s", hex.EncodeToString(pubBytes)))
	rec2 := httptest.NewRecorder()
	suite.echo.ServeHTTP(rec2, req2)
	assert.Equal(suite.T(), http.StatusOK, rec2.Code)
	assert.NoError(suite.T(), json.NewDecoder(rec2.Body).Decode(&responseBody))
	assert.EqualValues(suite.T(), testLogin, responseBody.Login)
	assert.EqualValues(suite.T(), newNickname, responseBody.Nickname)
	assert.EqualValues(suite.T(), hex.EncodeToString(messageSigned), responseBody.Password)
	user, err = suite.Service.FindUserByLoginOrNickname(context.Background(), newNickname)
	assert.NoError(suite.T(), err)
	assert.EqualValues(suite.T(), newNickname, user.Nickname)

	assert.NoError(suite.T(), json.NewEncoder(&buf).Encode(&ExpectedCreateUserRequestBody{
		Login:    testLogin,
		Password: hex.EncodeToString(messageSigned),
		Nickname: "", // to get the nickname
	}))
	req3 := httptest.NewRequest(http.MethodPost, "/v2/create", &buf)
	req3.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req3.Header.Add("Authorization", fmt.Sprintf("Bearer %s", hex.EncodeToString(pubBytes)))
	rec3 := httptest.NewRecorder()
	suite.echo.ServeHTTP(rec3, req3)
	assert.Equal(suite.T(), http.StatusOK, rec3.Code)
	assert.NoError(suite.T(), json.NewDecoder(rec3.Body).Decode(&responseBody))
	assert.EqualValues(suite.T(), testLogin, responseBody.Login)
	assert.EqualValues(suite.T(), newNickname, responseBody.Nickname)
	assert.EqualValues(suite.T(), hex.EncodeToString(messageSigned), responseBody.Password)
}

func (suite *UsersTestSuite) TestCreateWrongLogin() {
	e := echo.New()
	e.HTTPErrorHandler = responses.HTTPErrorHandler

	var buf bytes.Buffer
	e.Validator = &lib.CustomValidator{Validator: validator.New()}
	priv, err := crypto.UnmarshalPrivateKey(PRIV_KEY)
	assert.NoError(suite.T(), err)
	pub := priv.GetPublic().(*crypto.Ed25519PublicKey)
	pubBytes, _ := pub.Raw()
	messageSigned, err := priv.Sign([]byte(SIGNING_PHRASE))
	assert.NoError(suite.T(), err)

	pub_bytes, err := pub.Raw()
	assert.NoError(suite.T(), err)
	pubKey, err := crypto.UnmarshalEd25519PublicKey(pub_bytes)
	assert.NoError(suite.T(), err)
	principal, err := security.PrincipalFromPubKey(pubKey)
	assert.NoError(suite.T(), err)
	testLogin := principal.String() + "=="
	e.Validator = &lib.CustomValidator{Validator: validator.New()}

	assert.NoError(suite.T(), json.NewEncoder(&buf).Encode(&ExpectedCreateUserRequestBody{
		Login:    testLogin,
		Password: hex.EncodeToString(messageSigned),
	}))
	req := httptest.NewRequest(http.MethodPost, "/v2/create", &buf)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", hex.EncodeToString(pubBytes)))
	rec := httptest.NewRecorder()
	suite.echo.ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	responseBody := ExpectedCreateUserRequestBody{}
	assert.NoError(suite.T(), json.NewDecoder(rec.Body).Decode(&responseBody))
	assert.EqualValues(suite.T(), testLogin, responseBody.Login)
	assert.EqualValues(suite.T(), "", responseBody.Nickname)
	assert.EqualValues(suite.T(), hex.EncodeToString(messageSigned), responseBody.Password)
	user, err := suite.Service.FindUserByLoginOrNickname(context.Background(), testLogin)
	assert.NoError(suite.T(), err)
	assert.EqualValues(suite.T(), "", user.Nickname)
}

func (suite *UsersTestSuite) TestCreateWrongSignature() {
	e := echo.New()
	e.HTTPErrorHandler = responses.HTTPErrorHandler

	var buf bytes.Buffer
	e.Validator = &lib.CustomValidator{Validator: validator.New()}
	priv, err := crypto.UnmarshalPrivateKey(PRIV_KEY)
	assert.NoError(suite.T(), err)
	pub := priv.GetPublic().(*crypto.Ed25519PublicKey)
	pubBytes, _ := pub.Raw()
	messageSigned := make([]byte, 64)
	rand.Read(messageSigned)
	assert.NoError(suite.T(), err)
	pub_bytes, err := pub.Raw()
	assert.NoError(suite.T(), err)
	pubKey, err := crypto.UnmarshalEd25519PublicKey(pub_bytes)
	assert.NoError(suite.T(), err)
	principal, err := security.PrincipalFromPubKey(pubKey)
	assert.NoError(suite.T(), err)
	testLogin := principal.String()
	e.Validator = &lib.CustomValidator{Validator: validator.New()}

	assert.NoError(suite.T(), json.NewEncoder(&buf).Encode(&ExpectedCreateUserRequestBody{
		Login:    testLogin,
		Password: hex.EncodeToString(messageSigned),
	}))
	req := httptest.NewRequest(http.MethodPost, "/v2/create", &buf)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", hex.EncodeToString(pubBytes)))
	rec := httptest.NewRecorder()
	suite.echo.ServeHTTP(rec, req)
	assert.Equal(suite.T(), rec.Code, http.StatusUnauthorized)
}

func (suite *UsersTestSuite) TestCreateWithNoSignature() {
	e := echo.New()
	e.HTTPErrorHandler = responses.HTTPErrorHandler
	e.Validator = &lib.CustomValidator{Validator: validator.New()}
	var buf bytes.Buffer
	const testLogin = "Testlogin"
	const testPassword = "testPass"
	const testNickname = "testNickname"
	json.NewEncoder(&buf).Encode(&ExpectedCreateUserResponseBody{
		Login:    testLogin,
		Password: testPassword,
		Nickname: testNickname,
	})
	req := httptest.NewRequest(http.MethodPost, "/v2/create", &buf)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	suite.echo.ServeHTTP(rec, req)
	responseBody := ExpectedCreateUserRequestBody{}
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	assert.NoError(suite.T(), json.NewDecoder(rec.Body).Decode(&responseBody))
	assert.EqualValues(suite.T(), testLogin, responseBody.Login)
	assert.EqualValues(suite.T(), testNickname, responseBody.Nickname)
	assert.EqualValues(suite.T(), testPassword, responseBody.Password)
}

func (suite *UsersTestSuite) TestCreateTakenUserNickname() {
	e := echo.New()
	e.HTTPErrorHandler = responses.HTTPErrorHandler
	e.Validator = &lib.CustomValidator{Validator: validator.New()}
	var buf bytes.Buffer
	const takenLogin = "takenLogin"
	const takenPassword = "takenPass"
	const takenNickname = "takenNickname"
	json.NewEncoder(&buf).Encode(&ExpectedCreateUserResponseBody{
		Login:    takenLogin,
		Password: takenPassword,
		Nickname: takenNickname,
	})
	req := httptest.NewRequest(http.MethodPost, "/v2/create", &buf)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	suite.echo.ServeHTTP(rec, req)
	responseBody := ExpectedCreateUserRequestBody{}
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	assert.NoError(suite.T(), json.NewDecoder(rec.Body).Decode(&responseBody))
	assert.EqualValues(suite.T(), takenLogin, responseBody.Login)
	assert.EqualValues(suite.T(), takenNickname, responseBody.Nickname)
	assert.EqualValues(suite.T(), takenPassword, responseBody.Password)

	const newNickname = "newNickname"
	const newPassword = "newPassword"
	json.NewEncoder(&buf).Encode(&ExpectedCreateUserResponseBody{
		Login:    takenNickname,
		Password: newPassword,
		Nickname: newNickname,
	})
	req2 := httptest.NewRequest(http.MethodPost, "/v2/create", &buf)
	req2.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec2 := httptest.NewRecorder()
	suite.echo.ServeHTTP(rec2, req2)
	assert.Equal(suite.T(), http.StatusBadRequest, rec2.Code)

	const newLogin = "newLogin"
	json.NewEncoder(&buf).Encode(&ExpectedCreateUserResponseBody{
		Login:    newLogin,
		Password: newPassword,
		Nickname: takenLogin,
	})
	req3 := httptest.NewRequest(http.MethodPost, "/v2/create", &buf)
	req3.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec3 := httptest.NewRecorder()
	suite.echo.ServeHTTP(rec3, req3)
	assert.Equal(suite.T(), http.StatusBadRequest, rec3.Code)

	json.NewEncoder(&buf).Encode(&ExpectedCreateUserResponseBody{
		Login:    takenLogin,
		Password: newPassword,
		Nickname: newNickname,
	})
	req4 := httptest.NewRequest(http.MethodPost, "/v2/create", &buf)
	req4.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec4 := httptest.NewRecorder()
	suite.echo.ServeHTTP(rec4, req4)
	assert.Equal(suite.T(), http.StatusBadRequest, rec4.Code)

	json.NewEncoder(&buf).Encode(&ExpectedCreateUserResponseBody{
		Login:    newLogin,
		Password: newPassword,
		Nickname: takenNickname,
	})
	req5 := httptest.NewRequest(http.MethodPost, "/v2/create", &buf)
	req5.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec5 := httptest.NewRecorder()
	suite.echo.ServeHTTP(rec5, req5)
	assert.Equal(suite.T(), http.StatusBadRequest, rec5.Code)

	json.NewEncoder(&buf).Encode(&ExpectedCreateUserResponseBody{
		Login:    takenLogin,
		Password: takenPassword,
		Nickname: takenLogin,
	})
	req6 := httptest.NewRequest(http.MethodPost, "/v2/create", &buf)
	req6.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec6 := httptest.NewRecorder()
	suite.echo.ServeHTTP(rec6, req6)
	assert.Equal(suite.T(), http.StatusOK, rec6.Code)
	assert.NoError(suite.T(), json.NewDecoder(rec6.Body).Decode(&responseBody))
	assert.EqualValues(suite.T(), takenLogin, responseBody.Login)
	assert.EqualValues(suite.T(), takenLogin, responseBody.Nickname)
	assert.EqualValues(suite.T(), takenPassword, responseBody.Password)
	_, err := suite.Service.FindUserByNickname(context.Background(), takenNickname)
	assert.Error(suite.T(), err)

	json.NewEncoder(&buf).Encode(&ExpectedCreateUserResponseBody{
		Login:    takenLogin,
		Password: takenPassword,
		Nickname: takenLogin,
	})
	req7 := httptest.NewRequest(http.MethodPost, "/v2/create", &buf)
	req7.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec7 := httptest.NewRecorder()
	suite.echo.ServeHTTP(rec7, req7)
	assert.Equal(suite.T(), http.StatusOK, rec7.Code)
	assert.NoError(suite.T(), json.NewDecoder(rec7.Body).Decode(&responseBody))
	assert.EqualValues(suite.T(), takenLogin, responseBody.Login)
	assert.EqualValues(suite.T(), takenLogin, responseBody.Nickname)
	assert.EqualValues(suite.T(), takenPassword, responseBody.Password)
}

func (suite *UsersTestSuite) TestCreateWrongNickname() {
	e := echo.New()
	e.HTTPErrorHandler = responses.HTTPErrorHandler
	e.Validator = &lib.CustomValidator{Validator: validator.New()}
	var buf bytes.Buffer
	const testLogin = "Testlogin"
	const testPassword = "testPass"
	const testNickname = " testNickname"
	json.NewEncoder(&buf).Encode(&ExpectedCreateUserResponseBody{
		Login:    testLogin,
		Password: testPassword,
		Nickname: testNickname,
	})
	req := httptest.NewRequest(http.MethodPost, "/v2/create", &buf)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	suite.echo.ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusBadRequest, rec.Code)
}

func (suite *UsersTestSuite) TestCheckUsers() {
	e := echo.New()
	e.HTTPErrorHandler = responses.HTTPErrorHandler

	var buf bytes.Buffer
	e.Validator = &lib.CustomValidator{Validator: validator.New()}
	priv, err := crypto.UnmarshalPrivateKey(PRIV_KEY)
	assert.NoError(suite.T(), err)
	pub := priv.GetPublic().(*crypto.Ed25519PublicKey)
	pubBytes, _ := pub.Raw()
	messageSigned, err := priv.Sign([]byte(SIGNING_PHRASE))
	assert.NoError(suite.T(), err)

	pub_bytes, err := pub.Raw()
	assert.NoError(suite.T(), err)
	pubKey, err := crypto.UnmarshalEd25519PublicKey(pub_bytes)
	assert.NoError(suite.T(), err)
	principal, err := security.PrincipalFromPubKey(pubKey)
	assert.NoError(suite.T(), err)
	testLogin := principal.String()

	assert.NoError(suite.T(), json.NewEncoder(&buf).Encode(&ExpectedCreateUserRequestBody{
		Login:    testLogin,
		Password: hex.EncodeToString(messageSigned),
	}))
	req := httptest.NewRequest(http.MethodPost, "/v2/create", &buf)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", hex.EncodeToString(pubBytes)))
	rec := httptest.NewRecorder()
	suite.echo.ServeHTTP(rec, req)
	responseBody := ExpectedCreateUserRequestBody{}
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	assert.NoError(suite.T(), json.NewDecoder(rec.Body).Decode(&responseBody))
	assert.EqualValues(suite.T(), testLogin, responseBody.Login)
	assert.EqualValues(suite.T(), "", responseBody.Nickname)
	assert.EqualValues(suite.T(), hex.EncodeToString(messageSigned), responseBody.Password)
	user, err := suite.Service.FindUserByLoginOrNickname(context.Background(), testLogin)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), testLogin, user.Login)

	validUsers := v2controllers.CheckUsersResponseBody{}
	req2 := httptest.NewRequest(http.MethodGet, "/v2/check?user="+testLogin+"&user=fakeuser", nil)
	req2.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec2 := httptest.NewRecorder()
	suite.echo.ServeHTTP(rec2, req2)
	assert.Equal(suite.T(), http.StatusOK, rec2.Code)
	assert.NoError(suite.T(), json.NewDecoder(rec2.Body).Decode(&validUsers))
	assert.Len(suite.T(), validUsers.ExistingUsers, 1)
	assert.Equal(suite.T(), testLogin, validUsers.ExistingUsers[0])
}

func TestCreateUserV2TestSuite(t *testing.T) {
	suite.Run(t, new(UsersTestSuite))
}
