// SPDX-License-Identifier: Apache-2.0

package auditkind

// ServerRecoveryCheckpoint records offline quorum checkpoint acceptance and the
// cancellation of restored session/work authority before ingress is reopened.
var ServerRecoveryCheckpoint = kind("server.recovery_checkpoint_accepted")
