package vault

import (
	"fmt"
	"testing"
)

func TestFatalError(t *testing.T) {
	err := checkFatalError(fmt.Errorf("Code: 403"))
	if err != ErrPermissionDenied {
		t.Errorf("error should be permission denied got: %v", err)
	}

	err = checkFatalError(fmt.Errorf("lease not found or lease is not renewable"))
	if err != ErrLeaseNotFound {
		t.Errorf("error should be lease not found got: %v", err)
	}

	err = checkFatalError(fmt.Errorf("foo"))
	if err != nil {
		t.Errorf("error should be nil got: %v", err)
	}
}
