// SPDX-License-Identifier: MPL-2.0
package vault

import (
    "context"
    "testing"
    "github.com/openbao/openbao/v2/internal/helper/identity/mfa"
)

func TestTjippOktaUnavailable(t *testing.T) {
    core := &Core{}
    for _, config := range []*mfa.Config{nil, {}, {Name: "test"}} {
        if err := core.validateOkta(context.Background(), config, "synthetic"); err == nil {
            t.Fatal("removed Okta method must never authenticate")
        }
    }
}
