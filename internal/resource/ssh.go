// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"google.golang.org/protobuf/reflect/protoreflect"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

const (
	SSHBannerPath          = "/etc/issue.net"
	SSHBannerDirectivePath = "/etc/ssh/sshd_config.d/00-lindm-banner.conf"
)

// SSHBannerOnly is capability admission, not a second field validator. The
// banner provider must never silently ignore an authentication/network setting.
func SSHBannerOnly(desired *resourcev1.SSHServerDesired) bool {
	if desired == nil || desired.BannerText == nil {
		return false
	}
	only := true
	desired.ProtoReflect().Range(func(field protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		only = field.Name() == "banner_text"
		return only
	})
	return only
}
