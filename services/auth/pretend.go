// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"fmt"

	"code.gitea.io/gitea/models/organization"
	user_model "code.gitea.io/gitea/models/user"
)

const (
	// PretendOriginalUIDKey stores the authenticated user who started a pretend session.
	PretendOriginalUIDKey = "pretend_original_uid"
	// PretendOrgIDKey stores the organization which authorized the latest pretend switch.
	PretendOrgIDKey = "pretend_org_id"
)

// GetPretendOriginalUser returns the authenticated user who started the current pretend session.
func GetPretendOriginalUser(ctx context.Context, sess SessionStore) (*user_model.User, bool, error) {
	if sess == nil {
		return nil, false, nil
	}

	uidValue := sess.Get(PretendOriginalUIDKey)
	if uidValue == nil {
		return nil, false, nil
	}

	uid, ok := uidValue.(int64)
	if !ok || uid <= 0 {
		return nil, true, fmt.Errorf("invalid pretend original user ID in session: %T", uidValue)
	}

	user, err := user_model.GetUserByID(ctx, uid)
	if err != nil {
		return nil, true, fmt.Errorf("get pretend original user %d: %w", uid, err)
	}
	return user, true, nil
}

// ValidatePretendSession validates both the real user and the impersonated user against
// the organization which authorized the latest switch. It is intended to run on every
// authenticated web request so permission revocation takes effect immediately.
func ValidatePretendSession(ctx context.Context, sess SessionStore, currentUser *user_model.User) (*user_model.User, int64, bool, error) {
	originalUser, isPretending, err := GetPretendOriginalUser(ctx, sess)
	if err != nil || !isPretending {
		return originalUser, 0, isPretending, err
	}
	if originalUser == nil || !originalUser.IsActive || originalUser.ProhibitLogin || originalUser.IsOrganization() {
		return nil, 0, true, fmt.Errorf("pretend original user is not allowed to sign in")
	}
	if currentUser == nil || currentUser.IsAdmin || currentUser.IsOrganization() || !currentUser.IsActive || currentUser.ProhibitLogin {
		return nil, 0, true, fmt.Errorf("pretend target user is not eligible")
	}

	orgIDValue := sess.Get(PretendOrgIDKey)
	orgID, ok := orgIDValue.(int64)
	if !ok || orgID <= 0 {
		return nil, 0, true, fmt.Errorf("invalid pretend organization ID in session: %T", orgIDValue)
	}

	org, err := organization.GetOrgByID(ctx, orgID)
	if err != nil {
		return nil, 0, true, fmt.Errorf("get pretend organization %d: %w", orgID, err)
	}
	companyTeam, err := org.GetCompanyTeamForUser(ctx, originalUser)
	if err != nil || companyTeam == nil {
		return nil, 0, true, fmt.Errorf("original user is no longer allowed to pretend in organization %d: %w", orgID, err)
	}
	if !companyTeam.IsMember(ctx, currentUser.ID) {
		return nil, 0, true, fmt.Errorf("target user %d is no longer a company team member in organization %d", currentUser.ID, orgID)
	}

	return originalUser, orgID, true, nil
}
