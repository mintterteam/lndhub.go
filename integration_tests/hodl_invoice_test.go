package integration_tests

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/getAlby/lndhub.go/common"
	"github.com/getAlby/lndhub.go/controllers"
	"github.com/getAlby/lndhub.go/lib"
	"github.com/getAlby/lndhub.go/lib/responses"
	"github.com/getAlby/lndhub.go/lib/service"
	"github.com/getAlby/lndhub.go/lib/tokens"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type HodlInvoiceSuite struct {
	TestSuite
	mlnd                     *MockLND
	externalLND              *MockLND
	service                  *service.LndhubService
	userLogin                ExpectedCreateUserResponseBody
	userToken                string
	invoiceUpdateSubCancelFn context.CancelFunc
	hodlLND                  *LNDMockHodlWrapperAsync
}

func (suite *HodlInvoiceSuite) SetupSuite() {
	mlnd := newDefaultMockLND()
	externalLND, err := NewMockLND("1234567890abcdefabcd", 0, make(chan (*lnrpc.Invoice)))
	if err != nil {
		log.Fatalf("Error initializing test service: %v", err)
	}
	suite.externalLND = externalLND
	suite.mlnd = mlnd
	// inject hodl lnd client
	lndClient, err := NewLNDMockHodlWrapperAsync(mlnd)
	suite.hodlLND = lndClient
	if err != nil {
		log.Fatalf("Error setting up test client: %v", err)
	}

	svc, err := LndHubTestServiceInit(lndClient)
	if err != nil {
		log.Fatalf("Error initializing test service: %v", err)
	}
	users, userTokens, err := createUsers(svc, 1)
	if err != nil {
		log.Fatalf("Error creating test users: %v", err)
	}
	// Subscribe to LND invoice updates in the background
	// store cancel func to be called in tear down suite
	ctx, cancel := context.WithCancel(context.Background())
	suite.invoiceUpdateSubCancelFn = cancel
	go svc.InvoiceUpdateSubscription(ctx)
	suite.service = svc
	e := echo.New()

	e.HTTPErrorHandler = responses.HTTPErrorHandler
	e.Validator = &lib.CustomValidator{Validator: validator.New()}
	suite.echo = e
	assert.Equal(suite.T(), 1, len(users))
	assert.Equal(suite.T(), 1, len(userTokens))
	suite.userLogin = users[0]
	suite.userToken = userTokens[0]
	suite.echo.Use(tokens.Middleware([]byte(suite.service.Config.JWTSecret)))
	suite.echo.GET("/balance", controllers.NewBalanceController(suite.service).Balance)
	suite.echo.POST("/addinvoice", controllers.NewAddInvoiceController(suite.service).AddInvoice)
	suite.echo.POST("/payinvoice", controllers.NewPayInvoiceController(suite.service).PayInvoice)
}

func (suite *HodlInvoiceSuite) TestHodlInvoice() {
	userFundingSats := 1000
	externalSatRequested := 500
	// fund user account
	invoiceResponse := suite.createAddInvoiceReq(userFundingSats, "integration test external payment user", suite.userToken)
	err := suite.mlnd.mockPaidInvoice(invoiceResponse, 0, false, nil)
	assert.NoError(suite.T(), err)

	// wait a bit for the callback event to hit
	time.Sleep(10 * time.Millisecond)

	// create external invoice
	externalInvoice := lnrpc.Invoice{
		Memo:      "integration tests: external pay from user",
		Value:     int64(externalSatRequested),
		RPreimage: []byte("preimage1"),
	}
	invoice, err := suite.externalLND.AddInvoice(context.Background(), &externalInvoice)
	assert.NoError(suite.T(), err)
	// pay external from user, req will be canceled after 2 sec
	go suite.createPayInvoiceReqWithCancel(invoice.PaymentRequest, suite.userToken)

	// wait for payment to be updated as pending in database
	time.Sleep(5 * time.Second)

	// check to see that balance was reduced
	userId := getUserIdFromToken(suite.userToken)
	userBalance, err := suite.service.CurrentUserBalance(context.Background(), userId)
	if err != nil {
		fmt.Printf("Error when getting balance %v\n", err.Error())
	}
	assert.Equal(suite.T(), int64(userFundingSats-externalSatRequested), userBalance)

	// check payment is pending
	inv, err := suite.service.FindInvoiceByPaymentHashAndUser(context.Background(), userId, hex.EncodeToString(invoice.RHash))
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), common.InvoiceStateInitialized, inv.State)

	//start payment checking loop
	go func() {
		err = suite.service.CheckAllPendingOutgoingPayments(context.Background())
		assert.NoError(suite.T(), err)
	}()
	//wait a bit for routine to start
	time.Sleep(time.Second)
	//send cancel invoice with lnrpc.payment
	suite.hodlLND.SettlePayment(lnrpc.Payment{
		PaymentHash:     hex.EncodeToString(invoice.RHash),
		Value:           externalInvoice.Value,
		CreationDate:    0,
		Fee:             0,
		PaymentPreimage: "",
		ValueSat:        externalInvoice.Value,
		ValueMsat:       0,
		PaymentRequest:  invoice.PaymentRequest,
		Status:          lnrpc.Payment_FAILED,
		FailureReason:   lnrpc.PaymentFailureReason_FAILURE_REASON_INCORRECT_PAYMENT_DETAILS,
	})
	//wait a bit for db update to happen
	time.Sleep(time.Second)

	// check that balance was reverted and invoice is in error state
	userBalance, err = suite.service.CurrentUserBalance(context.Background(), userId)
	if err != nil {
		fmt.Printf("Error when getting balance %v\n", err.Error())
	}
	assert.Equal(suite.T(), int64(userFundingSats), userBalance)

	invoices, err := suite.service.InvoicesFor(context.Background(), userId, common.InvoiceTypeOutgoing)
	if err != nil {
		fmt.Printf("Error when getting invoices %v\n", err.Error())
	}
	assert.Equal(suite.T(), 1, len(invoices))
	assert.Equal(suite.T(), common.InvoiceStateError, invoices[0].State)
	errorString := "FAILURE_REASON_INCORRECT_PAYMENT_DETAILS"
	assert.Equal(suite.T(), errorString, invoices[0].ErrorMessage)

	transactonEntries, err := suite.service.TransactionEntriesFor(context.Background(), userId)
	if err != nil {
		fmt.Printf("Error when getting transaction entries %v\n", err.Error())
	}
	// check if there are 3 transaction entries, with reversed credit and debit account ids
	assert.Equal(suite.T(), 3, len(transactonEntries))
	assert.Equal(suite.T(), transactonEntries[1].CreditAccountID, transactonEntries[2].DebitAccountID)
	assert.Equal(suite.T(), transactonEntries[1].DebitAccountID, transactonEntries[2].CreditAccountID)
	assert.Equal(suite.T(), transactonEntries[1].Amount, int64(externalSatRequested))
	assert.Equal(suite.T(), transactonEntries[2].Amount, int64(externalSatRequested))

	// create external invoice
	externalInvoice = lnrpc.Invoice{
		Memo:      "integration tests: external pay from user",
		Value:     int64(externalSatRequested),
		RPreimage: []byte("preimage2"),
	}
	invoice, err = suite.externalLND.AddInvoice(context.Background(), &externalInvoice)
	assert.NoError(suite.T(), err)
	// pay external from user, req will be canceled after 2 sec
	go suite.createPayInvoiceReqWithCancel(invoice.PaymentRequest, suite.userToken)
	// wait for payment to be updated as pending in database
	time.Sleep(3 * time.Second)
	// check payment is pending
	inv, err = suite.service.FindInvoiceByPaymentHashAndUser(context.Background(), userId, hex.EncodeToString(invoice.RHash))
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), common.InvoiceStateInitialized, inv.State)
	//start payment checking loop
	go func() {
		err = suite.service.CheckAllPendingOutgoingPayments(context.Background())
		assert.NoError(suite.T(), err)
	}()
	//wait a bit for routine to start
	time.Sleep(time.Second)
	//send settle invoice with lnrpc.payment
	suite.hodlLND.SettlePayment(lnrpc.Payment{
		PaymentHash:     hex.EncodeToString(invoice.RHash),
		Value:           externalInvoice.Value,
		CreationDate:    0,
		Fee:             0,
		PaymentPreimage: "preimage2",
		ValueSat:        externalInvoice.Value,
		ValueMsat:       0,
		PaymentRequest:  invoice.PaymentRequest,
		Status:          lnrpc.Payment_SUCCEEDED,
		FailureReason:   0,
	})
	//wait a bit for db update to happen
	time.Sleep(time.Second)

	if err != nil {
		fmt.Printf("Error when getting balance %v\n", err.Error())
	}
	//fetch user balance again
	userBalance, err = suite.service.CurrentUserBalance(context.Background(), userId)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), int64(userFundingSats-externalSatRequested), userBalance)
	// check payment is updated as successful
	inv, err = suite.service.FindInvoiceByPaymentHashAndUser(context.Background(), userId, hex.EncodeToString(invoice.RHash))
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), common.InvoiceStateSettled, inv.State)
	clearTable(suite.service, "invoices")
	clearTable(suite.service, "transaction_entries")
	clearTable(suite.service, "accounts")
	clearTable(suite.service, "users")
}

func (suite *HodlInvoiceSuite) TearDownSuite() {
	suite.invoiceUpdateSubCancelFn()
}

func TestHodlInvoiceSuite(t *testing.T) {
	suite.Run(t, new(HodlInvoiceSuite))
}
