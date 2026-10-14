// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
)

// DirectoryReviewCookie is a real browser-kind session issued by code/PKCE.
// It belongs only in the review runner's private, temporary credential file.
type DirectoryReviewCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type DirectoryAuthorizationReviewConfig struct {
	Origin           string                  `json:"origin"`
	Address          string                  `json:"address"`
	OwnerCookies     []DirectoryReviewCookie `json:"ownerCookies"`
	ReaderUsername   string                  `json:"readerUsername"`
	ReaderPassword   string                  `json:"readerPassword"`
	KnownGroup       string                  `json:"knownGroup"`
	AdvancedGroup    string                  `json:"advancedGroup"`
	DeviceGroup      string                  `json:"deviceGroup"`
	AllowedDeviceID  string                  `json:"allowedDeviceId"`
	AllowedHostname  string                  `json:"allowedHostname"`
	ExcludedDeviceID string                  `json:"excludedDeviceId"`
	ExcludedHostname string                  `json:"excludedHostname"`
}

// DirectoryAuthorizationReview owns a real Keycloak human/group and console
// session. Device observations are separately supplied by the synthetic UI fixture.
type DirectoryAuthorizationReview struct {
	Config DirectoryAuthorizationReviewConfig
	owner  *OwnerSession
	reader *ApprovalSession
}

func (r *DirectoryAuthorizationReview) Close(ctx context.Context) error {
	r.Config.ReaderPassword = ""
	for i := range r.Config.OwnerCookies {
		r.Config.OwnerCookies[i].Value = ""
	}
	var result error
	if r.reader != nil {
		result = errors.Join(result, r.reader.Close(ctx))
	}
	if r.owner != nil {
		result = errors.Join(result, r.owner.Close(ctx))
	}
	return result
}

// OpenDirectoryAuthorizationReview changes only this disposable server and
// randomly owned provider objects; it adds no OAuth scope or provider catalog.
func (f *AuthorityFixture) OpenDirectoryAuthorizationReview(ctx context.Context, deviceIDs []string) (_ *DirectoryAuthorizationReview, resultErr error) {
	if f == nil || f.local != nil || f.persistent || f.connected != nil || f.database == nil || len(deviceIDs) != 2 {
		return nil, errors.New("directory UI review requires disposable directory authority and two synthetic devices")
	}
	review := new(DirectoryAuthorizationReview)
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, review.Close(context.WithoutCancel(ctx)))
		}
	}()
	var err error
	review.owner, err = f.OpenOwnerSession(ctx)
	if err != nil {
		return nil, err
	}
	review.reader, err = OpenApprovalSession(ctx, f.repository, f)
	if err != nil {
		return nil, err
	}
	owned := review.reader.directory
	reviewName := "directory-review-support-" + rand.Text()
	if err := owned.updateUser(ctx, map[string]any{"firstName": "Directory", "lastName": "Review support"}); err != nil {
		return nil, err
	}
	// The user's immutable ID is already known; the new name identifies only
	// the separately created group for create-response-loss cleanup.
	owned.name = reviewName
	groupPath := func(id string) (string, error) {
		_, body, err := owned.request(ctx, http.MethodGet, "/groups/"+id, nil, http.StatusOK)
		if err != nil {
			return "", err
		}
		var group struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(body, &group); err != nil {
			return "", err
		}
		if group.Path == "" {
			return "", errors.New("directory source did not return the group's source-issued path")
		}
		return group.Path, nil
	}
	known, err := groupPath(owned.groupID)
	if err != nil {
		return nil, err
	}
	owned.groupID, err = owned.create(ctx, "groups")
	if err != nil {
		return nil, err
	}
	if err := owned.membership(ctx, true); err != nil {
		return nil, err
	}
	advanced, err := groupPath(owned.groupID)
	if err != nil {
		return nil, err
	}
	group, err := review.owner.Admin.SetDeviceGroup(ctx, connect.NewRequest(&adminv1.SetDeviceGroupRequest{
		RequestId: uuid.NewString(), GroupId: uuid.NewString(), Name: "Directory review workstations", DeviceIds: deviceIDs[:1], CreateOnly: true, Reason: "scope real directory UI review to one synthetic device",
	}))
	if err != nil {
		return nil, err
	}
	state, err := review.owner.Admin.GetAuthorization(ctx, connect.NewRequest(&adminv1.GetAuthorizationRequest{}))
	if err != nil {
		return nil, err
	}
	policy := &authv1.AuthorizationPolicy{
		Roles:         []*authv1.RoleDefinition{{Name: "directory-review-reader", Permissions: []string{"fleet.read"}}, {Name: "directory-review-auditor", Permissions: []string{"fleet.read", "audit.read"}}},
		GroupBindings: []*authv1.GroupBinding{{Group: known, Role: "directory-review-reader", Scopes: []*authv1.DeviceScope{{GroupIds: []string{group.Msg.GetGroup().GetId()}}}}},
	}
	if _, err := review.owner.Admin.UpdateAuthorization(ctx, connect.NewRequest(&adminv1.UpdateAuthorizationRequest{RequestId: uuid.NewString(), ExpectedRevision: state.Msg.GetAuthorization().GetRevision(), Policy: policy, Reason: "prepare real directory-primary console review"})); err != nil {
		return nil, err
	}
	if err := review.reader.session.Close(ctx); err != nil {
		return nil, err
	}
	allowed, err := review.owner.Admin.GetDevice(ctx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: deviceIDs[0]}))
	if err != nil {
		return nil, err
	}
	excluded, err := review.owner.Admin.GetDevice(ctx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: deviceIDs[1]}))
	if err != nil {
		return nil, err
	}
	review.Config = DirectoryAuthorizationReviewConfig{
		Origin: consoleOrigin, Address: f.AdminAddress,
		ReaderUsername: review.reader.account.username, ReaderPassword: review.reader.account.password,
		KnownGroup: known, AdvancedGroup: advanced, DeviceGroup: group.Msg.GetGroup().GetName(),
		AllowedDeviceID: deviceIDs[0], AllowedHostname: allowed.Msg.GetDevice().GetHostname(),
		ExcludedDeviceID: deviceIDs[1], ExcludedHostname: excluded.Msg.GetDevice().GetHostname(),
	}
	origin, err := url.Parse(consoleOrigin)
	if err != nil {
		return nil, err
	}
	for _, cookie := range review.owner.client.Jar.Cookies(origin) {
		review.Config.OwnerCookies = append(review.Config.OwnerCookies, DirectoryReviewCookie{Name: cookie.Name, Value: cookie.Value})
	}
	if len(review.Config.OwnerCookies) == 0 {
		return nil, errors.New("real directory owner login did not issue a browser session")
	}
	return review, nil
}
