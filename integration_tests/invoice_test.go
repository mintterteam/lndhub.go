package integration_tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getAlby/lndhub.go/common"
	"github.com/getAlby/lndhub.go/controllers"
	v2controllers "github.com/getAlby/lndhub.go/controllers_v2"
	"github.com/getAlby/lndhub.go/lib"
	"github.com/getAlby/lndhub.go/lib/responses"
	"github.com/getAlby/lndhub.go/lib/service"
	"github.com/getAlby/lndhub.go/lib/tokens"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type InvoiceTestSuite struct {
	TestSuite
	service    *service.LndhubService
	aliceLogin ExpectedCreateUserResponseBody
	aliceToken string
}

func (suite *InvoiceTestSuite) SetupSuite() {
	svc, err := LndHubTestServiceInit(newDefaultMockLND())
	if err != nil {
		log.Fatalf("Error initializing test service: %v", err)
	}
	suite.service = svc
	users, userTokens, err := createUsers(svc, 1)
	if err != nil {
		log.Fatalf("Error creating test users: %v", err)
	}
	e := echo.New()

	e.HTTPErrorHandler = responses.HTTPErrorHandler
	e.Validator = &lib.CustomValidator{Validator: validator.New()}
	suite.echo = e
	assert.Equal(suite.T(), 1, len(users))
	assert.Equal(suite.T(), 1, len(userTokens))
	suite.aliceLogin = users[0]
	suite.aliceToken = userTokens[0]
	suite.echo.POST("/invoice/:user_login", controllers.NewInvoiceController(svc).Invoice)
	suite.echo.GET("/v2/invoicemeta/:payment_hash", v2controllers.NewInvoiceController(svc).GetInvoiceMeta)
	suite.echo.POST("/v2/invoices", v2controllers.NewInvoiceController(svc).AddInvoice, tokens.Middleware([]byte(suite.service.Config.JWTSecret)))
}

func (suite *InvoiceTestSuite) TearDownTest() {
	clearTable(suite.service, "invoices")
}

func (suite *InvoiceTestSuite) TestZeroAmtInvoice() {
	rec := httptest.NewRecorder()
	var buf bytes.Buffer
	assert.NoError(suite.T(), json.NewEncoder(&buf).Encode(&ExpectedV2AddInvoiceRequestBody{
		Amount: 0,
		Memo:   "test zero amount v2 invoice",
	}))
	req := httptest.NewRequest(http.MethodPost, "/v2/invoices", &buf)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", suite.aliceToken))
	suite.echo.ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
}

func (suite *InvoiceTestSuite) TestAddInvoiceWithoutToken() {
	user, _ := suite.service.FindUserByLogin(context.Background(), suite.aliceLogin.Login)
	invoicesBefore, _ := suite.service.InvoicesFor(context.Background(), user.ID, common.InvoiceTypeIncoming)
	assert.Equal(suite.T(), 0, len(invoicesBefore))

	suite.createInvoiceReq(10, "test invoice without token", suite.aliceLogin.Login)

	// check if invoice is added
	invoicesAfter, _ := suite.service.InvoicesFor(context.Background(), user.ID, common.InvoiceTypeIncoming)
	assert.Equal(suite.T(), 1, len(invoicesAfter))

}

func (suite *InvoiceTestSuite) TestGetInvoiceMetadata() {
	user, _ := suite.service.FindUserByLogin(context.Background(), suite.aliceLogin.Login)
	invoice := suite.createInvoiceReq(358, "My invoice", user.Login)

	// check if we can get the invoice
	invoiceResponse := []v2controllers.Invoice{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v2/invoicemeta/"+invoice.RHash+"?user="+user.Login, nil)
	suite.echo.ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	assert.NoError(suite.T(), json.NewDecoder(rec.Body).Decode(&invoiceResponse))
	assert.Equal(suite.T(), common.InvoiceStateOpen, invoiceResponse[0].Status)
	assert.EqualValues(suite.T(), 0, invoiceResponse[0].Amount)
}

func (suite *InvoiceTestSuite) TestAddInvoiceForNonExistingUser() {
	nonExistingLogin := suite.aliceLogin.Login + "abc"
	suite.createInvoiceReqError(10, "test invoice without token", nonExistingLogin)
}

func TestInvoiceSuite(t *testing.T) {
	suite.Run(t, new(InvoiceTestSuite))
}
