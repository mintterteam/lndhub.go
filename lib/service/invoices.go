package service

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/getAlby/lndhub.go/common"
	"github.com/getAlby/lndhub.go/db/models"
	"github.com/getAlby/lndhub.go/lib/responses"
	"github.com/getAlby/lndhub.go/lnd"
	"github.com/getsentry/sentry-go"
	"github.com/labstack/gommon/random"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/schema"
)

type Route struct {
	TotalAmt  int64 `json:"total_amt"`
	TotalFees int64 `json:"total_fees"`
}

type SendPaymentResponse struct {
	PaymentPreimage    []byte `json:"payment_preimage,omitempty"`
	PaymentPreimageStr string
	PaymentError       string `json:"payment_error,omitempty"`
	PaymentHash        []byte `json:"payment_hash,omitempty"`
	PaymentHashStr     string
	PaymentRoute       *Route
	TransactionEntry   *models.TransactionEntry
	Invoice            *models.Invoice
}

type Captable struct {
	// Invoice is the invoice that has been transmitted to LND.
	Invoice *models.Invoice
	// LeadingUserID is the ID of the user that is going to be paid in LND.
	LeadingUserID int64
	// SecondaryUsers are the rest of users (Excluding the leading user). Being the keys the lndhub IDs and the value the stake (0-1) on the invoice.
	SecondaryUsers map[int64]float64
}

func (svc *LndhubService) FindInvoiceByPaymentHashAndUser(ctx context.Context, userId int64, rHash string) (*models.Invoice, error) {
	var invoice models.Invoice

	err := svc.DB.NewSelect().Model(&invoice).Where("invoice.user_id = ? AND invoice.r_hash = ?", userId, rHash).Limit(1).Scan(ctx)
	if err != nil {
		return &invoice, err
	}
	return &invoice, nil
}

func (svc *LndhubService) FindInvoicesByPaymentHash(ctx context.Context, rHash string) ([]models.Invoice, error) {
	invoices := []models.Invoice{}
	err := svc.DB.NewSelect().Model(&invoices).Where("invoice.r_hash = ?", rHash).Scan(ctx)
	if err != nil {
		return invoices, err
	}
	return invoices, nil
}

func (svc *LndhubService) SendInternalPayment(ctx context.Context, invoice *models.Invoice) (sendPaymentResponse SendPaymentResponse, err error) {
	//Check if it's a keysend payment
	//If it is, an invoice will be created on-the-fly
	var incomingInvoice models.Invoice
	if invoice.Keysend {
		keysendInvoice, err := svc.HandleInternalKeysendPayment(ctx, invoice)
		if err != nil {
			return sendPaymentResponse, err
		}
		incomingInvoice = *keysendInvoice
	} else {
		// find invoice
		err := svc.DB.NewSelect().Model(&incomingInvoice).Where("(type = ? OR type = ?) AND r_hash = ? AND state = ? ", common.InvoiceTypeIncoming, common.InvoiceTypeSubinvoice, invoice.RHash, common.InvoiceStateOpen).Limit(1).Scan(ctx)
		if err != nil {
			// invoice not found or already settled
			// TODO: logging
			return sendPaymentResponse, err
		}
	}
	svc.Logger.Infof("Send Internal Invoice: invoice_id:%v value:%v state:%v", invoice.ID, invoice.Amount, invoice.State)

	// Get the user's current and incoming account for the transaction entry
	recipientCreditAccount, err := svc.AccountFor(ctx, common.AccountTypeCurrent, incomingInvoice.UserID)
	if err != nil {
		return sendPaymentResponse, err
	}
	recipientDebitAccount, err := svc.AccountFor(ctx, common.AccountTypeIncoming, incomingInvoice.UserID)
	if err != nil {
		return sendPaymentResponse, err
	}
	// create recipient entry
	recipientEntry := models.TransactionEntry{
		UserID:          incomingInvoice.UserID,
		InvoiceID:       incomingInvoice.ID,
		CreditAccountID: recipientCreditAccount.ID,
		DebitAccountID:  recipientDebitAccount.ID,
		Amount:          invoice.Amount,
	}
	_, err = svc.DB.NewInsert().Model(&recipientEntry).Exec(ctx)
	if err != nil {
		return sendPaymentResponse, err
	}

	// For internal invoices we know the preimage and we use that as a response
	// This allows wallets to get the correct preimage for a payment request even though NO lightning transaction was involved
	if incomingInvoice.Type == common.InvoiceTypeIncoming { // we don't want to return the sub_invoices
		preimage, _ := hex.DecodeString(incomingInvoice.Preimage)
		sendPaymentResponse.PaymentPreimageStr = incomingInvoice.Preimage
		sendPaymentResponse.PaymentPreimage = preimage
		sendPaymentResponse.Invoice = &incomingInvoice
		paymentHash, _ := hex.DecodeString(incomingInvoice.RHash)
		sendPaymentResponse.PaymentHashStr = incomingInvoice.RHash
		sendPaymentResponse.PaymentHash = paymentHash
		sendPaymentResponse.PaymentRoute = &Route{TotalAmt: incomingInvoice.Amount, TotalFees: 0}
	}
	incomingInvoice.Internal = true // mark incoming invoice as internal, just for documentation/debugging
	incomingInvoice.State = common.InvoiceStateSettled
	incomingInvoice.SettledAt = schema.NullTime{Time: time.Now()}
	incomingInvoice.Amount = invoice.Amount // set just in case of 0 amount invoice

	_, err = svc.DB.NewUpdate().Model(&incomingInvoice).WherePK().Exec(ctx)
	if err != nil {
		// could not save the invoice of the recipient
		return sendPaymentResponse, err
	}

	var subInvoice models.Invoice
	err = svc.DB.NewSelect().Model(&subInvoice).Where("type = ? AND preimage = ? AND add_index = ? AND state <> ? AND expires_at > ?",
		common.InvoiceTypeSubinvoice,
		incomingInvoice.Preimage,
		incomingInvoice.AddIndex,
		common.InvoiceStateSettled,
		time.Now()).Limit(1).Scan(ctx)

	if err == nil && subInvoice.AddIndex == incomingInvoice.AddIndex && incomingInvoice.State == common.InvoiceStateSettled {
		svc.Logger.Infof("Internal Payment subinvoice found, settling it.")
		// We update the rhash because we are going to find it later by rhash and we did
		// not copy the rhash when splitting the invoice (in order not to be prematurely discovered)
		subInvoice.RHash = incomingInvoice.RHash
		_, err = svc.DB.NewUpdate().Model(&subInvoice).WherePK().Exec(ctx)
		if err != nil {
			svc.Logger.Infof("Could not settle sub invoice %s", err.Error())
		}
		_, err = svc.SendInternalPayment(ctx, &subInvoice)
		if err == nil {
			// We decrease payer account
			// Get the user's current and outgoing account for the transaction entry
			userId := subInvoice.OriginUserID

			debitAccount, err := svc.AccountFor(ctx, common.AccountTypeCurrent, userId)
			if err != nil {
				svc.Logger.Errorf("Could not find current account user_id:%v", userId)
				return sendPaymentResponse, err
			}
			creditAccount, err := svc.AccountFor(ctx, common.AccountTypeOutgoing, userId)
			if err != nil {
				svc.Logger.Errorf("Could not find outgoing account user_id:%v", userId)
				return sendPaymentResponse, err
			}

			entry := models.TransactionEntry{
				UserID:          userId,
				InvoiceID:       subInvoice.ID,
				CreditAccountID: creditAccount.ID,
				DebitAccountID:  debitAccount.ID,
				Amount:          subInvoice.Amount,
			}

			// The DB constraints make sure the user actually has enough balance for the transaction
			// If the user does not have enough balance this call fails
			_, err = svc.DB.NewInsert().Model(&entry).Exec(ctx)
			if err != nil {
				svc.Logger.Errorf("Could not insert transaction entry user_id:%v invoice_id:%v", userId, invoice.ID)
				return sendPaymentResponse, err
			}
		}
	}

	svc.InvoicePubSub.Publish(strconv.FormatInt(incomingInvoice.UserID, 10), incomingInvoice)
	svc.InvoicePubSub.Publish(common.InvoiceTypeIncoming, incomingInvoice)

	return sendPaymentResponse, nil
}

func (svc *LndhubService) SendPaymentSync(ctx context.Context, invoice *models.Invoice) (SendPaymentResponse, error) {
	sendPaymentResponse := SendPaymentResponse{}

	sendPaymentRequest, err := svc.createLnRpcSendRequest(invoice)
	if err != nil {
		return sendPaymentResponse, err
	}

	// Execute the payment
	sendPaymentResult, err := svc.LndClient.SendPaymentSync(ctx, sendPaymentRequest)
	if err != nil {
		return sendPaymentResponse, err
	}

	// If there was a payment error we return an error
	if sendPaymentResult.GetPaymentError() != "" || sendPaymentResult.GetPaymentPreimage() == nil {
		return sendPaymentResponse, errors.New(sendPaymentResult.GetPaymentError())
	}

	preimage := sendPaymentResult.GetPaymentPreimage()
	sendPaymentResponse.PaymentPreimage = preimage
	sendPaymentResponse.PaymentPreimageStr = hex.EncodeToString(preimage[:])
	paymentHash := sendPaymentResult.GetPaymentHash()
	sendPaymentResponse.PaymentHash = paymentHash
	sendPaymentResponse.PaymentHashStr = hex.EncodeToString(paymentHash[:])
	sendPaymentResponse.PaymentRoute = &Route{TotalAmt: sendPaymentResult.PaymentRoute.TotalAmt, TotalFees: sendPaymentResult.PaymentRoute.TotalFees}
	return sendPaymentResponse, nil
}

func (svc *LndhubService) createLnRpcSendRequest(invoice *models.Invoice) (*lnrpc.SendRequest, error) {
	feeLimit := lnrpc.FeeLimit{
		Limit: &lnrpc.FeeLimit_Fixed{
			//if we get here, the destination is never ourselves, so we can use a dummy
			Fixed: svc.CalcFeeLimit("dummy", invoice.Amount),
		},
	}

	if !invoice.Keysend {
		// TODO(juligasa): uncomment when we actually store the custom records in the real invoice. RN we
		// only store it in the database but we don't inform LND of such custom records.
		/*
			if len(splits) > MAX_CUSTOM_RECORD_SIZE {
				return nil, fmt.Errorf("max custom records size is %d, but %d were given", MAX_CUSTOM_RECORD_SIZE, len(splits))
			}
		*/
		return &lnrpc.SendRequest{
			PaymentRequest: invoice.PaymentRequest,
			Amt:            invoice.Amount,
			FeeLimit:       &feeLimit,
			//DestCustomRecords: invoice.DestinationCustomRecords, #TODO(juligasa): Uncomment to actually store custom records
		}, nil
	}

	preImage, err := makePreimageHex()
	if err != nil {
		return nil, err
	}
	pHash := sha256.New()
	pHash.Write(preImage)
	// Prepare the LNRPC call
	//See: https://github.com/hsjoberg/blixt-wallet/blob/9fcc56a7dc25237bc14b85e6490adb9e044c009c/src/lndmobile/index.ts#L251-L270
	destBytes, err := hex.DecodeString(invoice.DestinationPubkeyHex)
	if err != nil {
		return nil, err
	}
	invoice.DestinationCustomRecords[KEYSEND_CUSTOM_RECORD] = preImage
	return &lnrpc.SendRequest{
		Dest:              destBytes,
		Amt:               invoice.Amount,
		PaymentHash:       pHash.Sum(nil),
		FeeLimit:          &feeLimit,
		DestFeatures:      []lnrpc.FeatureBit{lnrpc.FeatureBit_TLV_ONION_REQ},
		DestCustomRecords: invoice.DestinationCustomRecords,
	}, nil
}

func (svc *LndhubService) PayInvoice(ctx context.Context, invoice *models.Invoice) (*SendPaymentResponse, error) {
	userId := invoice.UserID

	// Get the user's current and outgoing account for the transaction entry
	debitAccount, err := svc.AccountFor(ctx, common.AccountTypeCurrent, userId)
	if err != nil {
		svc.Logger.Errorf("Could not find current account user_id:%v", userId)
		return nil, err
	}
	creditAccount, err := svc.AccountFor(ctx, common.AccountTypeOutgoing, userId)
	if err != nil {
		svc.Logger.Errorf("Could not find outgoing account user_id:%v", userId)
		return nil, err
	}
	svc.Logger.Infof("Pay Invoice: invoice_id:%v value:%v state:%v", invoice.ID, invoice.Amount, invoice.State)

	entry := models.TransactionEntry{
		UserID:          userId,
		InvoiceID:       invoice.ID,
		CreditAccountID: creditAccount.ID,
		DebitAccountID:  debitAccount.ID,
		Amount:          invoice.Amount,
	}

	// The DB constraints make sure the user actually has enough balance for the transaction
	// If the user does not have enough balance this call fails
	_, err = svc.DB.NewInsert().Model(&entry).Exec(ctx)
	if err != nil {
		svc.Logger.Errorf("Could not insert transaction entry user_id:%v invoice_id:%v", userId, invoice.ID)
		return nil, err
	}

	var paymentResponse SendPaymentResponse
	// Check the destination pubkey if it is an internal invoice and going to our node
	// Here we start using context.Background because we want to complete these calls
	// regardless of if the request's context is canceled or not.
	if svc.IdentityPubkey == invoice.DestinationPubkeyHex {
		paymentResponse, err = svc.SendInternalPayment(context.Background(), invoice)
		if err != nil {
			svc.HandleFailedPayment(context.Background(), invoice, entry, err)
			return nil, err
		}
	} else {
		paymentResponse, err = svc.SendPaymentSync(context.Background(), invoice)
		if err != nil {
			svc.HandleFailedPayment(context.Background(), invoice, entry, err)
			return nil, err
		}
	}

	paymentResponse.TransactionEntry = &entry

	// The payment was successful.
	// These changes to the invoice are persisted in the `HandleSuccessfulPayment` function
	invoice.Preimage = paymentResponse.PaymentPreimageStr
	invoice.Fee = paymentResponse.PaymentRoute.TotalFees
	invoice.RHash = paymentResponse.PaymentHashStr
	err = svc.HandleSuccessfulPayment(context.Background(), invoice, entry)
	return &paymentResponse, err
}

func (svc *LndhubService) HandleFailedPayment(ctx context.Context, invoice *models.Invoice, entryToRevert models.TransactionEntry, failedPaymentError error) error {
	// Process the tx insertion and invoice update in a DB transaction
	// analogous with the incoming invoice update
	tx, err := svc.DB.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		sentry.CaptureException(err)
		svc.Logger.Errorf("Could not open tx entry for updating failed payment:r_hash:%s %v", invoice.RHash, err)
		return err
	}
	// add transaction entry with reverted credit/debit account id
	entry := models.TransactionEntry{
		UserID:          invoice.UserID,
		InvoiceID:       invoice.ID,
		CreditAccountID: entryToRevert.DebitAccountID,
		DebitAccountID:  entryToRevert.CreditAccountID,
		Amount:          invoice.Amount,
	}
	_, err = tx.NewInsert().Model(&entry).Exec(ctx)
	if err != nil {
		tx.Rollback()
		sentry.CaptureException(err)
		svc.Logger.Errorf("Could not insert transaction entry user_id:%v invoice_id:%v error %s", invoice.UserID, invoice.ID, err.Error())
		return err
	}

	invoice.State = common.InvoiceStateError
	if failedPaymentError != nil {
		invoice.ErrorMessage = failedPaymentError.Error()
	}

	_, err = tx.NewUpdate().Model(invoice).WherePK().Exec(ctx)
	if err != nil {
		tx.Rollback()
		sentry.CaptureException(err)
		svc.Logger.Errorf("Could not update failed payment invoice user_id:%v invoice_id:%v error %s", invoice.UserID, invoice.ID, err.Error())
	}
	err = tx.Commit()
	if err != nil {
		sentry.CaptureException(err)
		svc.Logger.Errorf("Failed to commit DB transaction user_id:%v invoice_id:%v  %v", invoice.UserID, invoice.ID, err)
		return err
	}
	return err
}

func (svc *LndhubService) HandleSuccessfulPayment(ctx context.Context, invoice *models.Invoice, parentEntry models.TransactionEntry) error {
	invoice.State = common.InvoiceStateSettled
	invoice.SettledAt = schema.NullTime{Time: time.Now()}

	_, err := svc.DB.NewUpdate().Model(invoice).WherePK().Exec(ctx)
	if err != nil {
		sentry.CaptureException(err)
		svc.Logger.Errorf("Could not update successful payment invoice user_id:%v invoice_id:%v, error %s", invoice.UserID, invoice.ID, err.Error())
	}

	// Get the user's fee account for the transaction entry, current account is already there in parent entry
	feeAccount, err := svc.AccountFor(ctx, common.AccountTypeFees, invoice.UserID)
	if err != nil {
		svc.Logger.Errorf("Could not find fees account user_id:%v", invoice.UserID)
		return err
	}
	svc.Logger.Infof("Update Fee account: invoice_id:%v value:%v state:%v", invoice.ID, invoice.Amount, invoice.State)

	// add transaction entry for fee
	entry := models.TransactionEntry{
		UserID:          invoice.UserID,
		InvoiceID:       invoice.ID,
		CreditAccountID: feeAccount.ID,
		DebitAccountID:  parentEntry.DebitAccountID,
		Amount:          int64(invoice.Fee),
		ParentID:        parentEntry.ID,
	}
	_, err = svc.DB.NewInsert().Model(&entry).Exec(ctx)
	if err != nil {
		sentry.CaptureException(err)
		svc.Logger.Errorf("Could not insert fee transaction entry user_id:%v invoice_id:%v error %s", invoice.UserID, invoice.ID, err.Error())
		return err
	}

	userBalance, err := svc.CurrentUserBalance(ctx, entry.UserID)
	if err != nil {
		sentry.CaptureException(err)
		svc.Logger.Errorf("Could not fetch user balance user_id:%v invoice_id:%v error %s", invoice.UserID, invoice.ID, err.Error())
		return err
	}

	if userBalance < 0 {
		amountMsg := fmt.Sprintf("User balance is negative transaction_entry_id:%v user_id:%v amount:%v", entry.ID, entry.UserID, userBalance)
		svc.Logger.Info(amountMsg)
		sentry.CaptureMessage(amountMsg)
	}
	svc.InvoicePubSub.Publish(common.InvoiceTypeOutgoing, *invoice)

	return nil
}

func (svc *LndhubService) AddOutgoingInvoice(ctx context.Context, userID int64, paymentRequest string, lnPayReq *lnd.LNPayReq) (*models.Invoice, error) {
	// Initialize new DB invoice
	invoice := models.Invoice{
		Type:                 common.InvoiceTypeOutgoing,
		UserID:               userID,
		PaymentRequest:       paymentRequest,
		RHash:                lnPayReq.PayReq.PaymentHash,
		Amount:               lnPayReq.PayReq.NumSatoshis,
		State:                common.InvoiceStateInitialized,
		DestinationPubkeyHex: lnPayReq.PayReq.Destination,
		DescriptionHash:      lnPayReq.PayReq.DescriptionHash,
		Memo:                 lnPayReq.PayReq.Description,
		Keysend:              lnPayReq.Keysend,
		ExpiresAt:            bun.NullTime{Time: time.Unix(lnPayReq.PayReq.Timestamp, 0).Add(time.Duration(lnPayReq.PayReq.Expiry) * time.Second)},
	}

	// Save invoice
	_, err := svc.DB.NewInsert().Model(&invoice).Exec(ctx)
	if err != nil {
		return nil, err
	}
	return &invoice, nil
}

// If something goes wrong we should remove the lnd invoice with the same RHash. (cancel LND and remove from tables or cancel them common.InvoiceStateError,)
// When paid the leading invoice we should call sendInternalPayment, with all of the
// secondary and make sure it broadcasts all the split payments as well in the subscription methods (hooks).
func (svc *LndhubService) SplitIncomingPayment(ctx context.Context, captable Captable) error {
	for user, slice := range captable.SecondaryUsers {
		if user == captable.LeadingUserID {
			svc.Logger.Error(responses.LeadAuthorIncludedError.Error())
			return responses.LeadAuthorIncludedError
		}
		internalInvoice := models.Invoice{
			Type:                     common.InvoiceTypeSubinvoice,
			UserID:                   user,
			OriginUserID:             captable.LeadingUserID,
			Amount:                   int64(float64(captable.Invoice.Amount) * slice),
			Memo:                     captable.Invoice.Memo,
			State:                    common.InvoiceStateOpen,
			ExpiresAt:                captable.Invoice.ExpiresAt,
			DestinationCustomRecords: captable.Invoice.DestinationCustomRecords,
			PaymentRequest:           captable.Invoice.PaymentRequest,
			AddIndex:                 captable.Invoice.AddIndex,
			Preimage:                 captable.Invoice.Preimage,
			DestinationPubkeyHex:     captable.Invoice.DestinationPubkeyHex,
		}

		if _, err := svc.DB.NewInsert().Model(&internalInvoice).Exec(ctx); err != nil {
			svc.Logger.Error(responses.LeadAuthorIncludedError.Error())
			return err
		}
		svc.Logger.Infof("Adding Child invoice. userID [%v] invoiceID [%v] value [%v] description_hash [%s] memo [%s] captable [%v]", internalInvoice.UserID, internalInvoice.ID, internalInvoice.Amount, internalInvoice.DescriptionHash, internalInvoice.Memo, captable)

	}
	return nil
}

func (svc *LndhubService) AddIncomingInvoice(ctx context.Context, userID int64, amount int64, memo, descriptionHashStr string, splits ...byte) (*models.Invoice, error) {
	preimage, err := makePreimageHex()
	if err != nil {
		return nil, err
	}
	expiry := time.Hour * 24 // invoice expires in 24h
	customRecords := map[uint64][]byte{}
	if len(splits) > 0 {
		if len(splits) > MAX_CUSTOM_RECORD_SIZE {
			return nil, fmt.Errorf("max custom records size is %d, but %d were given", MAX_CUSTOM_RECORD_SIZE, len(splits))
		}
		customRecords[TLV_SPLIT_ID] = splits
	}
	// Initialize new DB invoice
	invoice := models.Invoice{
		Type:                     common.InvoiceTypeIncoming,
		UserID:                   userID,
		Amount:                   amount,
		Memo:                     memo,
		DescriptionHash:          descriptionHashStr,
		State:                    common.InvoiceStateInitialized,
		ExpiresAt:                bun.NullTime{Time: time.Now().Add(expiry)},
		DestinationCustomRecords: customRecords,
	}

	// Save invoice - we save the invoice early to have a record in case the LN call fails
	_, err = svc.DB.NewInsert().Model(&invoice).Exec(ctx)
	if err != nil {
		return nil, err
	}

	descriptionHash, err := hex.DecodeString(descriptionHashStr)
	if err != nil {
		return nil, err
	}
	// Initialize lnrpc invoice
	lnInvoice := lnrpc.Invoice{
		Memo:            memo,
		DescriptionHash: descriptionHash,
		Value:           amount,
		RPreimage:       preimage,
		Expiry:          int64(expiry.Seconds()),
	}
	// Call LND
	lnInvoiceResult, err := svc.LndClient.AddInvoice(ctx, &lnInvoice)
	if err != nil {
		_, err = svc.DB.NewDelete().Model(&invoice).Where("ID = ?", invoice.ID).Exec(ctx)
		if err != nil {
			svc.Logger.Errorf("Could not remove premature invoice ID %v we have an invoice that LND does not have!! Remove it manually", invoice.ID)
		}
		return nil, err
	}

	// Update the DB invoice with the data from the LND gRPC call
	invoice.PaymentRequest = lnInvoiceResult.PaymentRequest
	invoice.RHash = hex.EncodeToString(lnInvoiceResult.RHash)
	invoice.Preimage = hex.EncodeToString(preimage)
	invoice.AddIndex = lnInvoiceResult.AddIndex
	invoice.DestinationPubkeyHex = svc.IdentityPubkey // Our node pubkey for incoming invoices
	invoice.State = common.InvoiceStateOpen

	_, err = svc.DB.NewUpdate().Model(&invoice).WherePK().Exec(ctx)
	if err != nil {
		return nil, err
	}

	return &invoice, nil
}

func (svc *LndhubService) DecodePaymentRequest(ctx context.Context, bolt11 string) (*lnrpc.PayReq, error) {
	return svc.LndClient.DecodeBolt11(ctx, bolt11)
}

const hexBytes = random.Hex

func makePreimageHex() ([]byte, error) {
	return randBytesFromStr(32, hexBytes)
}
