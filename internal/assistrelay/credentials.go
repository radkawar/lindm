// SPDX-License-Identifier: Apache-2.0

package assistrelay

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 8489 long-term credentials and TURN REST passwords are HMAC-SHA1 by protocol.
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Credential roles. A device directive carries RoleDevice credentials and a
// console Join carries RoleConsole credentials for the same session.
const (
	RoleDevice  = "device"
	RoleConsole = "console"
)

var errCredential = errors.New("credential_rejected")

// credential is the parsed TURN REST username "<unix-expiry>:<session>:<role>".
type credential struct {
	expires time.Time
	session uuid.UUID
	role    string
}

func username(expires time.Time, session uuid.UUID, role string) string {
	return strconv.FormatInt(expires.Unix(), 10) + ":" + session.String() + ":" + role
}

func parseUsername(name string) (credential, error) {
	if len(name) > 128 {
		return credential{}, errCredential
	}
	parts := strings.Split(name, ":")
	if len(parts) != 3 || (parts[2] != RoleDevice && parts[2] != RoleConsole) {
		return credential{}, errCredential
	}
	expiry, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || expiry <= 0 || parts[0] != strconv.FormatInt(expiry, 10) {
		return credential{}, errCredential
	}
	session, err := uuid.Parse(parts[1])
	if err != nil || session == uuid.Nil || session.String() != parts[1] {
		return credential{}, errCredential
	}
	return credential{expires: time.Unix(expiry, 0), session: session, role: parts[2]}, nil
}

// password is base64(HMAC-SHA1(secret, username)), the TURN REST convention
// browsers and pion clients present as the long-term credential password.
func password(secret []byte, name string) string {
	mac := hmac.New(sha1.New, secret)
	mac.Write([]byte(name))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
