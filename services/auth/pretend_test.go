// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"testing"

	"code.gitea.io/gitea/models/db"
	"code.gitea.io/gitea/models/unittest"
	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/session"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidatePretendSession(t *testing.T) {
	assert.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.Other.CompanyTeamName, "team1")()

	store := session.NewMockStore("validate-pretend-session")
	require.NoError(t, store.Set(PretendOriginalUIDKey, int64(2)))
	require.NoError(t, store.Set(PretendOrgIDKey, int64(3)))

	target := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	original, orgID, pretending, err := ValidatePretendSession(db.DefaultContext, store, target)
	require.NoError(t, err)
	assert.True(t, pretending)
	assert.EqualValues(t, 2, original.ID)
	assert.EqualValues(t, 3, orgID)

	target.IsAdmin = true
	_, _, pretending, err = ValidatePretendSession(db.DefaultContext, store, target)
	assert.True(t, pretending)
	assert.Error(t, err)
}

func TestValidatePretendSessionRejectsRevokedOriginalUser(t *testing.T) {
	assert.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.Other.CompanyTeamName, "team1")()

	store := session.NewMockStore("revoked-pretend-session")
	require.NoError(t, store.Set(PretendOriginalUIDKey, int64(5)))
	require.NoError(t, store.Set(PretendOrgIDKey, int64(3)))
	target := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})

	_, _, pretending, err := ValidatePretendSession(db.DefaultContext, store, target)
	assert.True(t, pretending)
	assert.Error(t, err)
}
