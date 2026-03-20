package keyctl

import (
	"os"
	"testing"
)

func TestListKeyring(t *testing.T) {
	ring, err := UserSessionKeyring()
	if err != nil {
		t.Fatal(err)
	}

	keys, err := listKeys(keyId(ring.Id()))
	if err != nil {
		t.Fatal(err)
	}

	for _, k := range keys {
		t.Logf("id %v", k)
	}
}

func TestFSGID(t *testing.T) {
	gid, err := getfsgid()
	if err != nil {
		t.Fatal(err)
	}
	if int(gid) != os.Getegid() {
		t.Fatalf("getfsgid() returned unexpected results (%d!=%d)", gid, os.Getegid())
	}
	t.Logf("fsgid = %v\n", gid)
}

func TestKeyIdMethod(t *testing.T) {
	var id keyId = 42
	if id.Id() != 42 {
		t.Fatalf("keyId(42).Id() = %d, want 42", id.Id())
	}
}

func TestKeyctlCommandString(t *testing.T) {
	tests := []struct {
		cmd  keyctlCommand
		want string
	}{
		{keyctlGetKeyringId, "keyctlGetKeyringId"},
		{keyctlJoinSessionKeyring, "keyctlJoinSessionKeyring"},
		{keyctlUpdate, "keyctlUpdate"},
		{keyctlRevoke, "keyctlRevoke"},
		{keyctlChown, "keyctlChown"},
		{keyctlSetPerm, "keyctlSetPerm"},
		{keyctlDescribe, "keyctlDescribe"},
		{keyctlClear, "keyctlClear"},
		{keyctlLink, "keyctlLink"},
		{keyctlUnlink, "keyctlUnlink"},
		{keyctlSearch, "keyctlSearch"},
		{keyctlRead, "keyctlRead"},
		{keyctlInstantiate, "keyctlInstantiate"},
		{keyctlNegate, "keyctlNegate"},
		{keyctlSetReqKeyKeyring, "keyctlSetReqKeyKeyring"},
		{keyctlSetTimeout, "keyctlSetTimeout"},
		{keyctlAssumeAuthority, "keyctlAssumeAuthority"},
		{keyctlGetSecurity, "keyctlGetSecurity"},
		{keyctlSessionToParent, "keyctlSessionToParent"},
		{keyctlReject, "keyctlReject"},
		{keyctlInstantiateIov, "keyctlInstantiateIov"},
		{keyctlInvalidate, "keyctlInvalidate"},
		{keyctlGetPersistent, "keyctlGetPersistent"},
		{keyctlDhCompute, "keyctlDhCompute"},
		{keyctlPkeyQuery, "keyctlPkeyQuery"},
		{keyctlPkeyEncrypt, "keyctlPkeyEncrypt"},
		{keyctlPkeyDecrypt, "keyctlPkeyDecrypt"},
		{keyctlPkeySign, "keyctlPkeySign"},
		{keyctlPkeyVerify, "keyctlPkeyVerify"},
		{keyctlRestrictKeyring, "keyctlRestrictKeyring"},
		{keyctlMove, "keyctlMove"},
		{keyctlCapabilities, "keyctlCapabilities"},
		{keyctlWatchKey, "keyctlWatchKey"},
	}
	for _, tt := range tests {
		if got := tt.cmd.String(); got != tt.want {
			t.Errorf("keyctlCommand(%d).String() = %q, want %q", int(tt.cmd), got, tt.want)
		}
	}
}

func TestKeyctlCommandStringPanicsOnInvalid(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for invalid keyctlCommand, got none")
		}
	}()
	_ = keyctlCommand(9999).String()
}
