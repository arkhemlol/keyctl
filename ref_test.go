package keyctl

import (
	"errors"
	"os"
	"slices"
	"syscall"
	"testing"
)

func mustInfo(r Reference) Info {
	info, err := r.Info()
	if err != nil {
		if msg := err.Error(); msg == "key has expired" {
			return Info{Name: msg}
		}
	}
	return info
}

func helperTestKeyRefs(ring Keyring, t *testing.T) []Reference {
	var err error

	if ring == nil {
		if ring, err = SessionKeyring(); err != nil {
			t.Fatal(err)
		}
	}

	refs, err := ListKeyring(ring)
	if err != nil {
		t.Fatal(err)
	}

	for _, r := range refs {
		t.Logf("%d: %+v [%s]\n", r.Id, mustInfo(r), mustInfo(r).Permissions())
	}

	return refs
}

func filterErrno(e error, ignore ...syscall.Errno) error {
	if en, ok := e.(syscall.Errno); ok {
		if slices.Contains(ignore, en) {
			return nil
		}
	}

	return e
}

func helperRecurseKeyringRefs(kr Keyring, t *testing.T) {
	for _, r := range helperTestKeyRefs(kr, t) {
		if !r.Valid() {
			continue
		}
		key, err := r.Get()
		if filterErrno(err, syscall.EPERM, syscall.EACCES) != nil {
			t.Fatal(err)
		}
		if err != nil {
			return
		}
		switch k := key.(type) {
		case *namedKeyring:
			t.Logf("keyring %v: %q, parent %v", k.id, k.Name(), k.parent)
			helperRecurseKeyringRefs(k, t)
		case *keyring:
			t.Logf("keyring %v", k.id)
			helperRecurseKeyringRefs(k, t)
		case *Key:
			t.Logf("key %v: %q, keyring %v", k.id, k.Name, k.ring)
			data, err := k.Get()
			if filterErrno(err, syscall.EPERM, syscall.EACCES) != nil {
				t.Fatalf("%v %T(%d)", err, err, err)
			}
			t.Logf("   %v: %v", k.id, data)
		default:
			panic("unsupported type")
		}
	}
}

func TestSessionKeyringRefs(t *testing.T) {
	helperRecurseKeyringRefs(nil, t)
}

func TestInfoValid(t *testing.T) {
	if (Info{valid: true}).Valid() != true {
		t.Fatal("expected Valid()=true")
	}
	if (Info{valid: false}).Valid() != false {
		t.Fatal("expected Valid()=false")
	}
}

func TestInfoPermissionsUserBranch(t *testing.T) {
	info := Info{
		Uid:   os.Geteuid(),
		Gid:   -999,
		Perm:  PermUserAll | PermGroupView | PermOtherView,
		valid: true,
	}
	got := info.Permissions()
	want := encodePerms(0x3f)
	if got != want {
		t.Fatalf("Permissions() [user branch] = %q, want %q", got, want)
	}
}

func TestInfoPermissionsGroupBranch(t *testing.T) {
	info := Info{
		Uid:   -999,
		Gid:   os.Getegid(),
		Perm:  PermUserView | PermGroupAll | PermOtherView,
		valid: true,
	}
	got := info.Permissions()
	want := encodePerms(0x3f)
	if got != want {
		t.Fatalf("Permissions() [group branch] = %q, want %q", got, want)
	}
}

func TestInfoPermissionsOtherBranch(t *testing.T) {
	info := Info{
		Uid:   -999,
		Gid:   -999,
		Perm:  PermUserView | PermGroupView | PermOtherAll,
		valid: true,
	}
	got := info.Permissions()
	want := encodePerms(0x3f)
	if got != want {
		t.Fatalf("Permissions() [other branch] = %q, want %q", got, want)
	}
}

func TestReferenceValidOnKey(t *testing.T) {
	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}

	key, err := ring.Add("test-ref-valid", []byte("refdata"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := key.Unlink()
		if err != nil {
			t.Fatal(err)
		}
	}()

	ref := Reference{Id: key.Id(), parent: keyId(ring.Id())}
	if !ref.Valid() {
		t.Fatal("reference to existing key should be valid")
	}
}

func TestReferenceGetKey(t *testing.T) {
	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}

	key, err := ring.Add("test-ref-get", []byte("refgetdata"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := key.Unlink()
		if err != nil {
			t.Fatal(err)
		}
	}()

	ref := Reference{Id: key.Id(), parent: keyId(ring.Id())}
	obj, err := ref.Get()
	if err != nil {
		t.Fatal(err)
	}

	gotKey, ok := obj.(*Key)
	if !ok {
		t.Fatalf("expected *Key, got %T", obj)
	}
	if gotKey.Name != "test-ref-get" {
		t.Fatalf("key name = %q, want %q", gotKey.Name, "test-ref-get")
	}
}

func TestReferenceGetKeyring(t *testing.T) {
	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}

	nring, err := CreateKeyring(ring, "test-ref-get-ring")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := UnlinkKeyring(nring)
		if err != nil {
			t.Fatal(err)
		}
	}()

	ref := Reference{Id: nring.Id(), parent: keyId(ring.Id())}
	obj, err := ref.Get()
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := obj.(*namedKeyring); !ok {
		t.Fatalf("expected *namedKeyring, got %T", obj)
	}
}

func TestReferenceInfoCaching(t *testing.T) {
	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}

	key, err := ring.Add("test-ref-info-cache", []byte("cachedata"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := key.Unlink()
		if err != nil {
			t.Fatal(err)
		}
	}()

	ref := Reference{Id: key.Id(), parent: keyId(ring.Id())}

	info1, err := ref.Info()
	if err != nil {
		t.Fatal(err)
	}

	info2, err := ref.Info()
	if err != nil {
		t.Fatal(err)
	}

	if info1.Name != info2.Name {
		t.Fatalf("cached info mismatch: %q != %q", info1.Name, info2.Name)
	}
}

func TestReferenceValidOnExpiredKey(t *testing.T) {
	// A Reference pointing to a non-existent key id.
	// Info() will fail, so Valid() should return false.
	ref := Reference{Id: 0x7FFFFFFF}
	if ref.Valid() {
		t.Fatal("expected Valid()=false for non-existent key")
	}
}

func TestReferenceGetInvalidReference(t *testing.T) {
	// Pre-populate info with valid=false to hit the ErrInvalidReference branch.
	ref := Reference{
		Id:   1,
		info: &Info{valid: false},
	}
	_, err := ref.Get()
	if !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("expected ErrInvalidReference, got: %v", err)
	}
}

func TestReferenceGetUnsupportedType(t *testing.T) {
	// Pre-populate info with an unknown type to hit the default branch.
	ref := Reference{
		Id:   1,
		info: &Info{Type: "unsupported_type", valid: true},
	}
	_, err := ref.Get()
	if !errors.Is(err, ErrUnsupportedKeyType) {
		t.Fatalf("expected ErrUnsupportedKeyType, got: %v", err)
	}
}

func TestReferenceGetAnonymousKeyring(t *testing.T) {
	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}

	nring, err := CreateKeyring(ring, "test-anon-ref")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := UnlinkKeyring(nring)
		if err != nil {
			t.Fatal(err)
		}
	}()

	// Construct a Reference with Type="keyring" but empty Name
	// to hit the anonymous keyring branch (returns *keyring, not *namedKeyring).
	ref := Reference{
		Id:     nring.Id(),
		parent: keyId(ring.Id()),
		info:   &Info{Type: "keyring", Name: "", valid: true},
	}
	obj, err := ref.Get()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := obj.(*keyring); !ok {
		t.Fatalf("expected *keyring for anonymous keyring ref, got %T", obj)
	}
}
