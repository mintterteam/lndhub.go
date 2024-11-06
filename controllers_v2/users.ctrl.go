package v2controllers

import (
	"net/http"
	"strings"

	"github.com/getAlby/lndhub.go/lib/responses"
	"github.com/getAlby/lndhub.go/lib/service"
	"github.com/labstack/echo/v4"
)

// UsersController : Create user controller struct
type UsersController struct {
	svc *service.LndhubService
}

func NewUsersController(svc *service.LndhubService) *UsersController {
	return &UsersController{svc: svc}
}

type CreateUserResponseBody struct {
	Login    string `json:"login"`
	Password string `json:"password"`
	Nickname string `json:"nickname"`
}
type CreateUserRequestBody struct {
	Login    string `json:"login"`
	Password string `json:"password"`
	Nickname string `json:"nickname"`
}

// CreateUser godoc
// @Summary      Create an account
// @Description  Create a new account with a login and password. If login is an libp2p CID then the password must be the signature("log in into lndhub: <accountID>)") and the pubkey must be present in the auth header.
// @Accept       json
// @Produce      json
// @Tags         Account
// @Param        account  body      CreateUserRequestBody  false  "Create User"
// @Success      200      {object}  CreateUserResponseBody
// @Failure      400      {object}  responses.ErrorResponse
// @Failure      500      {object}  responses.ErrorResponse
// @Router       /v2/users [post]
func (controller *UsersController) CreateUser(c echo.Context) error {

	var body CreateUserRequestBody

	if err := c.Bind(&body); err != nil {
		c.Logger().Errorf("Failed to load create user request body: %v", err)
		return c.JSON(http.StatusBadRequest, responses.BadArgumentsError)
	}

	user, err := controller.svc.CreateUser(c.Request().Context(), body.Login, body.Password, body.Nickname)
	if err != nil {
		c.Logger().Errorf("Failed to create user: %v", err)
		if strings.Contains(err.Error(), responses.LoginTakenError.Message) ||
			(strings.Contains(err.Error(), "duplicate") && strings.Contains(err.Error(), "login")) {
			return c.JSON(http.StatusBadRequest, responses.LoginTakenError)
		} else if strings.Contains(err.Error(), responses.NicknameTakenError.Message) ||
			(strings.Contains(err.Error(), "duplicate") && strings.Contains(err.Error(), "nickname")) {
			return c.JSON(http.StatusBadRequest, responses.NicknameTakenError)
		} else if strings.Contains(err.Error(), responses.NicknameFormatError.Message) {
			return c.JSON(http.StatusBadRequest, responses.NicknameFormatError)
		} else {
			return c.JSON(http.StatusBadRequest, responses.BadArgumentsError)
		}

	}

	var ResponseBody CreateUserResponseBody
	ResponseBody.Login = user.Login
	ResponseBody.Password = user.Password
	ResponseBody.Nickname = user.Nickname

	return c.JSON(http.StatusOK, &ResponseBody)
}

type CheckUsersResponseBody struct {
	ExistingUsers []string `json:"existing_users"`
}

// CheckUsers godoc
// @Summary      Check if a list of users exist in the database.
// @Description  In order to know beforehand if the payment is going to succeed, the client should check that all users involved exists.
// @Accept       json
// @Produce      json
// @Tags         CheckUsers
// @Param        account  body      CheckUsersRequestBody  false  "Check User"
// @Success      200      {object}  CheckUsersResponseBody
// @Failure      400      {object}  responses.ErrorResponse
// @Failure      500      {object}  responses.ErrorResponse
// @Router       /v2/users [get]
func (controller *UsersController) CheckUsers(c echo.Context) error {
	// The user param could be userID (login) or a nickname (lnaddress)
	c.Response().Header().Set("Access-Control-Allow-Origin", "*")
	c.Response().Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
	c.Response().Header().Set("Access-Control-Allow-Methods", "OPTIONS, GET")
	if !c.QueryParams().Has("user") {
		c.Logger().Errorf("user mandatory param in query URL")
		return c.JSON(http.StatusBadRequest, responses.LnurlpBadArgumentsError)
	}
	responseBody := CheckUsersResponseBody{}
	for _, user := range c.QueryParams()["user"] {
		_, err := controller.svc.FindUserByLoginOrNickname(c.Request().Context(), user)
		if err != nil {
			c.Logger().Errorf("Failed to find user by login or nickname: user %v error %v", user, err)
			continue
		}
		responseBody.ExistingUsers = append(responseBody.ExistingUsers, user)
	}

	return c.JSON(http.StatusOK, &responseBody)
}
