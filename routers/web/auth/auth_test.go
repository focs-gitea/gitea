// Copyright 2024 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	auth_model "code.gitea.io/gitea/models/auth"
	"code.gitea.io/gitea/models/db"
	"code.gitea.io/gitea/models/unittest"
	"code.gitea.io/gitea/modules/session"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/test"
	"code.gitea.io/gitea/modules/util"
	auth_service "code.gitea.io/gitea/services/auth"
	"code.gitea.io/gitea/services/auth/source/oauth2"
	"code.gitea.io/gitea/services/context"
	"code.gitea.io/gitea/services/contexttest"

	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/stretchr/testify/assert"
)

func addOAuth2Source(t *testing.T, authName string, cfg oauth2.Source) {
	cfg.Provider = util.IfZero(cfg.Provider, "gitea")
	err := auth_model.CreateSource(db.DefaultContext, &auth_model.Source{
		Type:     auth_model.OAuth2,
		Name:     authName,
		IsActive: true,
		Cfg:      &cfg,
	})
	assert.NoError(t, err)
}

type mockCSRFProtector struct{}

func (mockCSRFProtector) GetHeaderName() string         { return "X-Csrf-Token" }
func (mockCSRFProtector) GetFormName() string           { return "_csrf" }
func (mockCSRFProtector) GetToken() string              { return "test-csrf-token" }
func (mockCSRFProtector) Validate(*context.Context)     {}
func (mockCSRFProtector) DeleteCookie(*context.Context) {}

func TestUserLogin(t *testing.T) {
	ctx, resp := contexttest.MockContext(t, "/user/login")
	SignIn(ctx)
	assert.Equal(t, http.StatusOK, resp.Code)

	ctx, resp = contexttest.MockContext(t, "/user/login")
	ctx.IsSigned = true
	SignIn(ctx)
	assert.Equal(t, http.StatusSeeOther, resp.Code)
	assert.Equal(t, "/", test.RedirectURL(resp))

	ctx, resp = contexttest.MockContext(t, "/user/login?redirect_to=/other")
	ctx.IsSigned = true
	SignIn(ctx)
	assert.Equal(t, "/other", test.RedirectURL(resp))

	ctx, resp = contexttest.MockContext(t, "/user/login")
	ctx.Req.AddCookie(&http.Cookie{Name: "redirect_to", Value: "/other-cookie"})
	ctx.IsSigned = true
	SignIn(ctx)
	assert.Equal(t, "/other-cookie", test.RedirectURL(resp))

	ctx, resp = contexttest.MockContext(t, "/user/login?redirect_to="+url.QueryEscape("https://example.com"))
	ctx.IsSigned = true
	SignIn(ctx)
	assert.Equal(t, "/", test.RedirectURL(resp))
}

func TestSignUpOAuth2ButMissingFields(t *testing.T) {
	defer test.MockVariableValue(&setting.OAuth2Client.EnableAutoRegistration, true)()
	defer test.MockVariableValue(&gothic.CompleteUserAuth, func(res http.ResponseWriter, req *http.Request) (goth.User, error) {
		return goth.User{Provider: "dummy-auth-source", UserID: "dummy-user"}, nil
	})()

	addOAuth2Source(t, "dummy-auth-source", oauth2.Source{})

	mockOpt := contexttest.MockContextOption{SessionStore: session.NewMockStore("dummy-sid")}
	ctx, resp := contexttest.MockContext(t, "/user/oauth2/dummy-auth-source/callback?code=dummy-code", mockOpt)
	ctx.SetParams("provider", "dummy-auth-source")
	SignInOAuthCallback(ctx)
	assert.Equal(t, http.StatusSeeOther, resp.Code)
	assert.Equal(t, "/user/link_account", test.RedirectURL(resp))

	// then the user will be redirected to the link account page, and see a message about the missing fields
	ctx, _ = contexttest.MockContext(t, "/user/link_account", mockOpt)
	LinkAccount(ctx)
	assert.EqualValues(t, "auth.oauth_callback_unable_auto_reg:dummy-auth-source,email", ctx.Data["AutoRegistrationFailedPrompt"])
}

func newPretendTestContext(t *testing.T, store *session.MockStore, doerID, targetID, orgID int64) (*context.Context, *httptest.ResponseRecorder) {
	t.Helper()
	ctx, resp := contexttest.MockContext(t, "POST /user/pretend/"+strconv.FormatInt(targetID, 10), contexttest.MockContextOption{SessionStore: store})
	contexttest.LoadUser(t, ctx, doerID)
	ctx.IsSigned = true
	ctx.Csrf = mockCSRFProtector{}
	ctx.SetParams("userid", strconv.FormatInt(targetID, 10))
	ctx.Req.Form.Set("org_id", strconv.FormatInt(orgID, 10))
	ctx.Req.Form.Set("redirect_to", "/org3")
	return ctx, resp
}

func TestPretendAndRestoreSession(t *testing.T) {
	assert.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.Other.CompanyTeamName, "team1")()

	store := session.NewMockStore("pretend-session")
	assert.NoError(t, store.Set("uid", int64(2)))
	assert.NoError(t, store.Set("uname", "user2"))

	ctx, resp := newPretendTestContext(t, store, 2, 4, 3)
	Pretend(ctx)
	assert.Equal(t, http.StatusSeeOther, resp.Code)
	assert.Equal(t, "/org3", test.RedirectURL(resp))
	assert.EqualValues(t, 4, store.Get("uid"))
	assert.EqualValues(t, 2, store.Get(auth_service.PretendOriginalUIDKey))
	assert.EqualValues(t, 3, store.Get(auth_service.PretendOrgIDKey))
	for _, cookie := range resp.Result().Cookies() {
		assert.NotEqual(t, setting.CookieRememberName, cookie.Name, "pretend must not create a remember cookie for the target user")
	}

	ctx, resp = newPretendTestContext(t, store, 4, 2, 3)
	Pretend(ctx)
	assert.Equal(t, http.StatusSeeOther, resp.Code)
	assert.Equal(t, "/org3", test.RedirectURL(resp))
	assert.EqualValues(t, 2, store.Get("uid"))
	assert.Nil(t, store.Get(auth_service.PretendOriginalUIDKey))
	assert.Nil(t, store.Get(auth_service.PretendOrgIDKey))
}

func TestPretendUsesOriginalUserForAuthorization(t *testing.T) {
	assert.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.Other.CompanyTeamName, "review_team")()

	store := session.NewMockStore("pretend-switch-session")
	assert.NoError(t, store.Set("uid", int64(15)))
	assert.NoError(t, store.Set("uname", "user15"))

	ctx, resp := newPretendTestContext(t, store, 15, 20, 17)
	Pretend(ctx)
	assert.Equal(t, http.StatusSeeOther, resp.Code)
	assert.EqualValues(t, 20, store.Get("uid"))
	assert.EqualValues(t, 15, store.Get(auth_service.PretendOriginalUIDKey))

	// user20 is the current identity, but user15 remains the real authorizer and may
	// switch to another member without losing the original identity.
	ctx, resp = newPretendTestContext(t, store, 20, 29, 17)
	Pretend(ctx)
	assert.Equal(t, http.StatusSeeOther, resp.Code)
	assert.EqualValues(t, 29, store.Get("uid"))
	assert.EqualValues(t, 15, store.Get(auth_service.PretendOriginalUIDKey))
}

func TestPretendRejectsUnauthorizedUser(t *testing.T) {
	assert.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.Other.CompanyTeamName, "team1")()

	store := session.NewMockStore("unauthorized-pretend-session")
	assert.NoError(t, store.Set("uid", int64(5)))
	assert.NoError(t, store.Set("uname", "user5"))

	ctx, resp := newPretendTestContext(t, store, 5, 4, 3)
	Pretend(ctx)
	assert.Equal(t, http.StatusNotFound, resp.Code)
	assert.EqualValues(t, 5, store.Get("uid"))
	assert.Nil(t, store.Get(auth_service.PretendOriginalUIDKey))
}
