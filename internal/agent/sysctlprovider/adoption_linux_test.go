// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sysctlprovider

import (
	"errors"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/admissiondetail"
)

func TestCreateOnlyLiveKeyRequiresAdoption(t *testing.T) {
	owner := &agentv1.ResourceOwnershipBinding{Policy: &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY}}
	err := acquisitionAllowed(owner, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if !errors.Is(err, ErrAdoptionRequired) || !errors.Is(err, ErrConflict) || admissiondetail.Of(err) != "existing_kernel_setting" {
		t.Fatalf("live key acquired under CREATE_ONLY: %v", err)
	}
	owner.Policy.Mode = resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION
	if err := acquisitionAllowed(owner, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); err != nil {
		t.Fatal(err)
	}
}
