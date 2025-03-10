package v2controllers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/getAlby/lndhub.go/common"
	"github.com/getAlby/lndhub.go/lib/responses"
	"github.com/getAlby/lndhub.go/lib/service"
	"github.com/getsentry/sentry-go"
	"github.com/labstack/echo/v4"
)

// InvoiceController : Add invoice controller struct
type InvoiceController struct {
	svc *service.LndhubService
}

func NewInvoiceController(svc *service.LndhubService) *InvoiceController {
	return &InvoiceController{svc: svc}
}

type Invoice struct {
	PaymentHash     string            `json:"payment_hash"`
	PaymentRequest  string            `json:"payment_request"`
	Description     string            `json:"description"`
	DescriptionHash string            `json:"description_hash,omitempty"`
	PaymentPreimage string            `json:"payment_preimage,omitempty"`
	Destination     string            `json:"destination"`
	Amount          int64             `json:"amount"`
	Fee             int64             `json:"fee"`
	Status          string            `json:"status"`
	Type            string            `json:"type"`
	ErrorMessage    string            `json:"error_message,omitempty"`
	SettledAt       time.Time         `json:"settled_at"`
	ExpiresAt       time.Time         `json:"expires_at"`
	IsPaid          bool              `json:"is_paid"`
	Keysend         bool              `json:"keysend"`
	CustomRecords   map[uint64][]byte `json:"custom_records,omitempty"`
}

// GetOutgoingInvoices godoc
// @Summary      Retrieve outgoing payments
// @Description  Returns a list of outgoing payments for a user
// @Accept       json
// @Produce      json
// @Tags         Invoice
// @Success      200  {object}  []Invoice
// @Failure      400  {object}  responses.ErrorResponse
// @Failure      500  {object}  responses.ErrorResponse
// @Router       /v2/invoices/outgoing [get]
// @Security     OAuth2Password
func (controller *InvoiceController) GetOutgoingInvoices(c echo.Context) error {
	userId := c.Get("UserID").(int64)

	invoices, err := controller.svc.InvoicesFor(c.Request().Context(), userId, common.InvoiceTypeOutgoing)
	if err != nil {
		return err
	}

	response := make([]Invoice, len(invoices))
	for i, invoice := range invoices {
		response[i] = Invoice{
			PaymentHash:     invoice.RHash,
			PaymentRequest:  invoice.PaymentRequest,
			Description:     invoice.Memo,
			DescriptionHash: invoice.DescriptionHash,
			PaymentPreimage: invoice.Preimage,
			Destination:     invoice.DestinationPubkeyHex,
			Amount:          invoice.Amount,
			Fee:             invoice.Fee,
			Status:          invoice.State,
			Type:            common.InvoiceTypePaid,
			ErrorMessage:    invoice.ErrorMessage,
			SettledAt:       invoice.SettledAt.Time,
			ExpiresAt:       invoice.ExpiresAt.Time,
			IsPaid:          invoice.State == common.InvoiceStateSettled,
			Keysend:         invoice.Keysend,
			CustomRecords:   invoice.DestinationCustomRecords,
		}
	}
	return c.JSON(http.StatusOK, &GetInvoicesResponseBody{Invoices: response})
}

// GetIncomingInvoices godoc
// @Summary      Retrieve incoming invoices
// @Description  Returns a list of incoming invoices for a user
// @Accept       json
// @Produce      json
// @Tags         Invoice
// @Success      200  {object}  []Invoice
// @Failure      400  {object}  responses.ErrorResponse
// @Failure      500  {object}  responses.ErrorResponse
// @Router       /v2/invoices/incoming [get]
// @Security     OAuth2Password
func (controller *InvoiceController) GetIncomingInvoices(c echo.Context) error {
	userId := c.Get("UserID").(int64)

	invoices, err := controller.svc.InvoicesIncomingAndInternalFor(c.Request().Context(), userId)
	if err != nil {
		return err
	}

	response := []Invoice{}
	for _, invoice := range invoices {
		// not allowing to view open subinvoices because they cannot be externally settled.
		if invoice.Type == common.InvoiceTypeSubinvoice && invoice.State != common.InvoiceStateSettled {
			continue
		}
		response = append(response, Invoice{
			PaymentHash:     invoice.RHash,
			PaymentRequest:  invoice.PaymentRequest,
			Description:     invoice.Memo,
			DescriptionHash: invoice.DescriptionHash,
			Destination:     invoice.DestinationPubkeyHex,
			Amount:          invoice.Amount,
			Fee:             invoice.Fee,
			Status:          invoice.State,
			Type:            common.InvoiceTypeUser,
			ErrorMessage:    invoice.ErrorMessage,
			SettledAt:       invoice.SettledAt.Time,
			ExpiresAt:       invoice.ExpiresAt.Time,
			IsPaid:          invoice.State == common.InvoiceStateSettled,
			Keysend:         invoice.Keysend,
			CustomRecords:   invoice.DestinationCustomRecords,
		})
	}
	return c.JSON(http.StatusOK, &GetInvoicesResponseBody{Invoices: response})
}

type AddInvoiceRequestBody struct {
	Amount          int64  `json:"amount" validate:"gte=0"`
	Description     string `json:"description"`
	DescriptionHash string `json:"description_hash" validate:"omitempty,hexadecimal,len=64"`
}

// AddInvoiceResponseBody kept because some clients use this
// strunct rather than the lndhub lud6 one.
type AddInvoiceResponseBody struct {
	PaymentHash    string    `json:"payment_hash"`
	PaymentRequest string    `json:"payment_request"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type GetInvoicesResponseBody struct {
	Invoices []Invoice `json:"invoices"`
}

// Lud6InvoiceResponseBody must comply with lud6
// https://github.com/lnurl/luds/blob/luds/06.md
type Lud6InvoiceResponseBody struct {
	Payreq      string   `json:"pr"`
	Routes      []string `json:"routes"`
	PaymentHash string   `json:"payment_hash" validate:"omitempty"` // custom field
}

type PaymentMetadata struct {
	Source  string             `json:"source"`
	Authors map[string]float64 `json:"authors"`
}

// URL returns the information in PaymentMetadata in URL-like fashion:
func (pmd *PaymentMetadata) URL() string {
	var url string
	if pmd.Source != "" {
		url += "source=" + pmd.Source
	}

	for acc, slice := range pmd.Authors {
		if url != "" {
			url += "&"
		}
		url += "user=" + acc + "," + fmt.Sprintf("%4.2f", slice)
	}
	return url
}

// AddInvoice godoc
// @Summary      Generate a new invoice
// @Description  Returns a new bolt11 invoice
// @Accept       json
// @Produce      json
// @Tags         Invoice
// @Param        invoice  body      AddInvoiceRequestBody  True  "Add Invoice"
// @Success      200      {object}  AddInvoiceResponseBody
// @Failure      400      {object}  responses.ErrorResponse
// @Failure      500      {object}  responses.ErrorResponse
// @Router       /v2/addinvoice [post]
// @Security     OAuth2Password
func (controller *InvoiceController) AddInvoice(c echo.Context) error {
	userID := c.Get("UserID").(int64)
	var body AddInvoiceRequestBody

	if err := c.Bind(&body); err != nil {
		c.Logger().Errorf("Failed to load addinvoice request body: %v", err)
		return c.JSON(http.StatusBadRequest, responses.BadArgumentsError)
	}

	if err := c.Validate(&body); err != nil {
		c.Logger().Errorf("Invalid addinvoice request body: %v", err)
		return c.JSON(http.StatusBadRequest, responses.BadArgumentsError)
	}

	controller.svc.Logger.Infof("Adding invoice: user_id:%v memo:%s value:%v description_hash:%s",
		userID, body.Description, body.Amount, body.DescriptionHash)

	invoice, err := controller.svc.AddIncomingInvoice(c.Request().Context(), userID, body.Amount, body.Description, body.DescriptionHash)
	if err != nil {
		c.Logger().Errorf("Error creating invoice: user_id:%v error: %v", userID, err)
		sentry.CaptureException(err)
		return c.JSON(http.StatusBadRequest, responses.BadArgumentsError)
	}
	responseBody := AddInvoiceResponseBody{
		PaymentHash:    invoice.RHash,
		PaymentRequest: invoice.PaymentRequest,
		ExpiresAt:      invoice.ExpiresAt.Time,
	}

	return c.JSON(http.StatusOK, &responseBody)
}

// GetInvoice godoc
// @Summary      Get a specific invoice
// @Description  Retrieve information about a specific invoice by payment hash
// @Accept       json
// @Produce      json
// @Tags         Invoice
// @Param        payment_hash  path      string  true  "Payment hash"
// @Success      200  {object}  Invoice
// @Failure      400  {object}  responses.ErrorResponse
// @Failure      500  {object}  responses.ErrorResponse
// @Router       /v2/invoices/{payment_hash} [get]
// @Security     OAuth2Password
func (controller *InvoiceController) GetInvoice(c echo.Context) error {
	userID := c.Get("UserID").(int64)
	rHash := c.Param("payment_hash")
	invoice, err := controller.svc.FindInvoiceByPaymentHashAndUser(c.Request().Context(), userID, rHash)
	// Probably we did not find the invoice
	if err != nil {
		c.Logger().Errorf("Invalid invoices request user_id:%v payment_hash:%s", userID, rHash)
		return c.JSON(http.StatusBadRequest, responses.BadArgumentsError)
	}
	if invoice.Type == common.InvoiceTypeSubinvoice && invoice.State != common.InvoiceStateSettled {
		controller.svc.Logger.Info("Cannot show an open sub invoice to the user yet")
		return c.JSON(http.StatusBadRequest, responses.BadArgumentsError)
	}
	responseBody := Invoice{
		PaymentHash:     invoice.RHash,
		PaymentRequest:  invoice.PaymentRequest,
		Description:     invoice.Memo,
		DescriptionHash: invoice.DescriptionHash,
		PaymentPreimage: invoice.Preimage,
		Destination:     invoice.DestinationPubkeyHex,
		Amount:          invoice.Amount,
		Fee:             invoice.Fee,
		Status:          invoice.State,
		Type:            invoice.Type,
		ErrorMessage:    invoice.ErrorMessage,
		SettledAt:       invoice.SettledAt.Time,
		ExpiresAt:       invoice.ExpiresAt.Time,
		IsPaid:          invoice.State == common.InvoiceStateSettled,
		Keysend:         invoice.Keysend,
		CustomRecords:   invoice.DestinationCustomRecords,
	}
	return c.JSON(http.StatusOK, &responseBody)
}

// GetInvoice godoc
// @Summary      Get a specific invoice
// @Description  Retrieve metadata about a specific invoice by payment hash
// @Accept       json
// @Produce      json
// @Tags         Invoice
// @Param        payment_hash  path      string  true  "Payment hash"
// @Success      200  {object}  Invoice
// @Failure      400  {object}  responses.ErrorResponse
// @Failure      500  {object}  responses.ErrorResponse
// @Router       /v2/invoicemeta/{payment_hash} [get]
// @Security     OAuth2Password
func (controller *InvoiceController) GetInvoiceMeta(c echo.Context) error {
	c.Response().Header().Set("Access-Control-Allow-Origin", "*")
	c.Response().Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
	c.Response().Header().Set("Access-Control-Allow-Methods", "OPTIONS, GET")

	rHash := c.Param("payment_hash")
	responseBody := []Invoice{}
	if !c.QueryParams().Has("user") {
		invoices, err := controller.svc.FindInvoicesByPaymentHash(c.Request().Context(), rHash)
		// Probably we did not find the invoice
		if err != nil {
			c.Logger().Errorf("Invalid invoices request payment_hash:%s", rHash)
			return c.JSON(http.StatusBadRequest, responses.BadArgumentsError)
		}
		for _, invoice := range invoices {
			responseBody = append(responseBody, Invoice{
				DescriptionHash: invoice.DescriptionHash,
				Status:          invoice.State,
				Type:            invoice.Type,
				ErrorMessage:    invoice.ErrorMessage,
				SettledAt:       invoice.SettledAt.Time,
				ExpiresAt:       invoice.ExpiresAt.Time,
				CustomRecords:   invoice.DestinationCustomRecords,
			})
		}
		return c.JSON(http.StatusOK, &responseBody)
	}
	userStr := c.QueryParam("user")
	user, err := controller.svc.FindUserByLogin(c.Request().Context(), userStr)
	if err != nil {
		c.Logger().Errorf("Failed to find user by login: user %v error %v", user.ID, err)
		return c.JSON(http.StatusBadRequest, responses.BadArgumentsError)
	}

	invoice, err := controller.svc.FindInvoiceByPaymentHashAndUser(c.Request().Context(), user.ID, rHash)
	// Probably we did not find the invoice
	if err != nil {
		c.Logger().Errorf("Invalid invoices request user_id:%v payment_hash:%s", user.ID, rHash)
		return c.JSON(http.StatusBadRequest, responses.BadArgumentsError)
	}

	responseBody = append(responseBody, Invoice{
		DescriptionHash: invoice.DescriptionHash,
		Status:          invoice.State,
		Type:            invoice.Type,
		ErrorMessage:    invoice.ErrorMessage,
		SettledAt:       invoice.SettledAt.Time,
		ExpiresAt:       invoice.ExpiresAt.Time,
		CustomRecords:   invoice.DestinationCustomRecords,
	})
	return c.JSON(http.StatusOK, &responseBody)
}
