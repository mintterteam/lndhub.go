package integration_tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getAlby/lndhub.go/controllers"
	"github.com/getAlby/lndhub.go/lib"
	"github.com/getAlby/lndhub.go/lib/responses"
	"github.com/getAlby/lndhub.go/lib/service"
	"github.com/getAlby/lndhub.go/lib/tokens"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type CreateUserTestSuite struct {
	suite.Suite
	Service *service.LndhubService
}

func (suite *CreateUserTestSuite) SetupSuite() {
	svc, err := LndHubTestServiceInit(newDefaultMockLND())
	if err != nil {
		log.Fatalf("Error initializing test service: %v", err)
	}
	suite.Service = svc
}

func (suite *CreateUserTestSuite) TearDownSuite() {

}

func (suite *CreateUserTestSuite) TearDownTest() {
	err := clearTable(suite.Service, "users")
	if err != nil {
		fmt.Printf("Tear down test error %v\n", err.Error())
		return
	}
	fmt.Println("Tear down test success")
}

func (suite *CreateUserTestSuite) TestCreate() {
	e := echo.New()
	e.HTTPErrorHandler = responses.HTTPErrorHandler
	e.Validator = &lib.CustomValidator{Validator: validator.New()}
	req := httptest.NewRequest(http.MethodPost, "/create", bytes.NewReader([]byte{}))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	controller := controllers.NewCreateUserController(suite.Service)
	responseBody := ExpectedCreateUserResponseBody{}
	if assert.NoError(suite.T(), controller.CreateUser(c)) {
		assert.Equal(suite.T(), http.StatusOK, rec.Code)
		assert.NoError(suite.T(), json.NewDecoder(rec.Body).Decode(&responseBody))
		assert.NotEmpty(suite.T(), responseBody.Login)
		assert.NotEmpty(suite.T(), responseBody.Password)
		fmt.Printf("Successfully created user with login %s\n", responseBody.Login)
	}
}
func (suite *CreateUserTestSuite) TestAdminCreate() {
	adminToken := "admin_token"
	e := echo.New()
	e.HTTPErrorHandler = responses.HTTPErrorHandler
	e.Validator = &lib.CustomValidator{Validator: validator.New()}
	controller := controllers.NewCreateUserController(suite.Service)
	e.POST("/create", controller.CreateUser, tokens.AdminTokenMiddleware(adminToken))
	req := httptest.NewRequest(http.MethodPost, "/create", bytes.NewReader([]byte{}))
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusBadRequest, rec.Code)
	req.Header.Set("Authorization", "Bearer not_the_admin_token")
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusUnauthorized, rec.Code)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adminToken))
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
}

func (suite *CreateUserTestSuite) TestCreateWithProvidedLoginAndPassword() {
	e := echo.New()
	e.HTTPErrorHandler = responses.HTTPErrorHandler
	e.Validator = &lib.CustomValidator{Validator: validator.New()}
	var buf bytes.Buffer
	const testLogin = "test login"
	const testPassword = "test password"
	json.NewEncoder(&buf).Encode(&ExpectedCreateUserRequestBody{
		Login:    testLogin,
		Password: testPassword,
	})
	req := httptest.NewRequest(http.MethodPost, "/create", &buf)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	controller := controllers.NewCreateUserController(suite.Service)
	responseBody := ExpectedCreateUserResponseBody{}
	if assert.NoError(suite.T(), controller.CreateUser(c)) {
		assert.Equal(suite.T(), http.StatusOK, rec.Code)
		assert.NoError(suite.T(), json.NewDecoder(rec.Body).Decode(&responseBody))
		assert.Equal(suite.T(), testLogin, responseBody.Login)
		assert.Equal(suite.T(), testPassword, responseBody.Password)
		fmt.Printf("Sucessfully created user with login %s\n", responseBody.Login)
	}
}

func TestCreateUserTestSuite(t *testing.T) {
	suite.Run(t, new(CreateUserTestSuite))
}
