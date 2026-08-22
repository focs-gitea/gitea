// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"net/http"
	"testing"

	"code.gitea.io/gitea/modules/setting"
	module_test "code.gitea.io/gitea/modules/test"
	"code.gitea.io/gitea/tests"

	"github.com/stretchr/testify/assert"
)

func assertSignedInAs(t *testing.T, session *TestSession, username string) *HTMLDoc {
	t.Helper()
	resp := session.MakeRequest(t, NewRequest(t, "GET", "/user/settings"), http.StatusOK)
	doc := NewHTMLParser(t, resp.Body)
	assert.Equal(t, username, doc.GetInputValueByID("username"))
	return doc
}

func TestPretendPostAndRestore(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer module_test.MockVariableValue(&setting.Other.CompanyTeamName, "team1")()

	session := loginUser(t, "user2")

	// The old state-changing GET endpoint must no longer exist.
	req := NewRequest(t, "GET", "/user/pretend/4?org_id=3&redirect_to=/org3")
	session.MakeRequest(t, req, http.StatusNotFound)

	// A POST without a valid CSRF token is rejected and does not change identity.
	req = NewRequestWithValues(t, "POST", "/user/pretend/4", map[string]string{
		"org_id":      "3",
		"redirect_to": "/org3",
	})
	session.MakeRequest(t, req, http.StatusSeeOther)
	assertSignedInAs(t, session, "user2")

	csrf := GetCSRF(t, session, "/org3")
	req = NewRequestWithValues(t, "POST", "/user/pretend/4", map[string]string{
		"_csrf":       csrf,
		"org_id":      "3",
		"redirect_to": "/org3",
	})
	session.MakeRequest(t, req, http.StatusSeeOther)

	doc := assertSignedInAs(t, session, "user4")
	assert.Equal(t, 1, doc.Find(`form[action="/user/pretend/2"]`).Length())

	csrf = doc.GetCSRF()
	req = NewRequestWithValues(t, "POST", "/user/pretend/2", map[string]string{
		"_csrf":       csrf,
		"org_id":      "3",
		"redirect_to": "/org3",
	})
	session.MakeRequest(t, req, http.StatusSeeOther)
	assertSignedInAs(t, session, "user2")
}
