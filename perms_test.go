package keyctl

import (
	"os"
	"testing"
)

func TestEncodePermsNone(t *testing.T) {
	result := encodePerms(0)
	expected := "--------"
	if result != expected {
		t.Fatalf("encodePerms(0) = %q, want %q", result, expected)
	}
}

func TestEncodePermsAll(t *testing.T) {
	result := encodePerms(0x3f)
	expected := "--alswrv"
	if result != expected {
		t.Fatalf("encodePerms(0x3f) = %q, want %q", result, expected)
	}
}

func TestEncodePermsViewOnly(t *testing.T) {
	result := encodePerms(0x01)
	expected := "-------v"
	if result != expected {
		t.Fatalf("encodePerms(0x01) = %q, want %q", result, expected)
	}
}

func TestEncodePermsReadOnly(t *testing.T) {
	result := encodePerms(0x02)
	expected := "------r-"
	if result != expected {
		t.Fatalf("encodePerms(0x02) = %q, want %q", result, expected)
	}
}

func TestEncodePermsReadView(t *testing.T) {
	result := encodePerms(0x03)
	expected := "------rv"
	if result != expected {
		t.Fatalf("encodePerms(0x03) = %q, want %q", result, expected)
	}
}

func TestEncodePermsFullByte(t *testing.T) {
	// Only the low 6 bits map to permission chars; top 2 bits map to "--"
	// positions which are always dashes. 0xff should look the same as 0x3f.
	result := encodePerms(0xff)
	expected := "--alswrv"
	if result != expected {
		t.Fatalf("encodePerms(0xff) = %q, want %q", result, expected)
	}
}

func TestKeyPermOtherMethod(t *testing.T) {
	p := PermOtherView | PermOtherRead
	got := p.Other()
	want := "------rv"
	if got != want {
		t.Fatalf("Other() = %q, want %q", got, want)
	}
}

func TestKeyPermGroupMethod(t *testing.T) {
	p := PermGroupView | PermGroupRead | PermGroupSearch
	got := p.Group()
	want := "----s-rv"
	if got != want {
		t.Fatalf("Group() = %q, want %q", got, want)
	}
}

func TestKeyPermUserMethod(t *testing.T) {
	got := PermUserAll.User()
	want := "--alswrv"
	if got != want {
		t.Fatalf("User() = %q, want %q", got, want)
	}
}

func TestKeyPermProcessMethod(t *testing.T) {
	got := PermProcessAll.Process()
	want := "--alswrv"
	if got != want {
		t.Fatalf("Process() = %q, want %q", got, want)
	}
}

func TestKeyPermProcessMethodPartial(t *testing.T) {
	// ProcessView = bit24 → byte val 0x01, ProcessWrite = bit26 → byte val 0x04
	p := PermProcessView | PermProcessWrite
	got := p.Process()
	want := "-----w-v"
	if got != want {
		t.Fatalf("Process() = %q, want %q", got, want)
	}
}

func TestKeyPermStringAllPerms(t *testing.T) {
	p := PermProcessAll | PermUserAll | PermGroupAll | PermOtherAll
	got := p.String()
	want := "alswrvalswrvalswrvalswrv"
	if got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestKeyPermStringZero(t *testing.T) {
	got := KeyPerm(0).String()
	want := "------------------------"
	if got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestKeyPermStringMixed(t *testing.T) {
	p := PermUserAll | PermOtherView
	got := p.String()
	// Process="------", User="alswrv", Group="------", Other="-----v"
	want := "------alswrv-----------v"
	if got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestPermConstantAggregation(t *testing.T) {
	allOther := PermOtherView | PermOtherRead | PermOtherWrite | PermOtherSearch | PermOtherLink | PermOtherSetattr
	if PermOtherAll != allOther {
		t.Fatalf("PermOtherAll = 0x%x, want 0x%x", PermOtherAll, allOther)
	}

	allGroup := PermGroupView | PermGroupRead | PermGroupWrite | PermGroupSearch | PermGroupLink | PermGroupSetattr
	if PermGroupAll != allGroup {
		t.Fatalf("PermGroupAll = 0x%x, want 0x%x", PermGroupAll, allGroup)
	}

	allUser := PermUserView | PermUserRead | PermUserWrite | PermUserSearch | PermUserLink | PermUserSetattr
	if PermUserAll != allUser {
		t.Fatalf("PermUserAll = 0x%x, want 0x%x", PermUserAll, allUser)
	}

	allProc := PermProcessView | PermProcessRead | PermProcessWrite | PermProcessSearch | PermProcessLink | PermProcessSetattr
	if PermProcessAll != allProc {
		t.Fatalf("PermProcessAll = 0x%x, want 0x%x", PermProcessAll, allProc)
	}
}

func TestSetPermOnKey(t *testing.T) {
	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}

	key, err := ring.Add("test-setperm", []byte("permdata"))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Unlink()

	perm := PermUserAll | PermProcessAll
	if err := SetPerm(key, perm); err != nil {
		t.Fatal(err)
	}

	info, err := key.Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.Perm&PermUserAll != PermUserAll {
		t.Fatalf("expected user-all bits set, got 0x%x", info.Perm)
	}
	t.Logf("permissions after SetPerm: %s (0x%x)", info.Perm, uint32(info.Perm))
}

func TestChownKey(t *testing.T) {
	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}

	key, err := ring.Add("test-chown", []byte("chowndata"))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Unlink()

	uid := os.Getuid()
	if err := Chown(key, uid); err != nil {
		t.Fatal(err)
	}
	t.Logf("chown key %v to uid %d succeeded", key.Id(), uid)
}

func TestChgrpKey(t *testing.T) {
	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}

	key, err := ring.Add("test-chgrp", []byte("chgrpdata"))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Unlink()

	gid := os.Getgid()
	if err := Chgrp(key, gid); err != nil {
		t.Fatal(err)
	}
	t.Logf("chgrp key %v to gid %d succeeded", key.Id(), gid)
}
