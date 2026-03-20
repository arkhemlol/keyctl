package keyctl

import (
	"testing"
)

func TestAdd100BytesToSessionKeyring(t *testing.T) {
	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}
	key, err := ring.Add("blank", make([]byte, 100))
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("added 100 byte empty key as: %v\n", key.Id())

	buf, err := key.Get()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("read %d octets from key: %v\n", len(buf), buf)
}

func TestAdd128BytesToSessionExpireAfter10Seconds(t *testing.T) {
	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}
	ring.SetDefaultTimeout(10)
	key, err := ring.Add("expire-test", make([]byte, 128))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("added 128 byte empty key as: %v\n", key.Id())
}

func TestFetchKey(t *testing.T) {
	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}
	key, err := ring.Search("blank")
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1024)
	r := NewReader(key)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("read %d octets from key: %v\n", n, buf[:n])
}

func TestFetchKeyFail(t *testing.T) {
	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}
	_, err = ring.Search("abigbunchofnonsense")
	if err == nil {
		t.Fatal("search expected to fail")
	}
}

func TestUnlinkKey(t *testing.T) {
	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}
	key, err := ring.Search("blank")
	if err != nil {
		t.Fatal(err)
	}
	if err = key.Unlink(); err != nil {
		t.Fatal(err)
	}
}

func helperTestCreateKeyring(ring Keyring, name string, t *testing.T) NamedKeyring {
	var err error

	if ring == nil {
		ring, err = SessionKeyring()
		if err != nil {
			t.Fatal(err)
		}
	}

	if name == "" {
		name = "testring"
	}
	ring, err = CreateKeyring(ring, name)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("created keyring %v named %q", ring.Id(), ring.(NamedKeyring).Name())
	return ring.(NamedKeyring)
}

func TestCreateKeyring(t *testing.T) {
	ring := helperTestCreateKeyring(nil, "", t)

	err := SetKeyringTTL(ring, 10)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateNestedKeyring(t *testing.T) {
	ring := helperTestCreateKeyring(nil, "", t)

	err := SetKeyringTTL(ring, 30)
	if err != nil {
		t.Fatal(err)
	}

	ring = helperTestCreateKeyring(ring, "testring2", t)
	t.Logf("created nested keyring %v named %q", ring.Id(), ring.Name())
	ring = helperTestCreateKeyring(ring, "testring3", t)
	t.Logf("created nested keyring %v named %q", ring.Id(), ring.Name())
}

func TestOpenNestedKeyring(t *testing.T) {
	us, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}
	ring := helperTestCreateKeyring(us, "", t)

	err = SetKeyringTTL(ring, 30)
	if err != nil {
		t.Fatal(err)
	}

	ring = helperTestCreateKeyring(ring, "testring2", t)
	t.Logf("created nested keyring %v named %q", ring.Id(), ring.Name())
	ring = helperTestCreateKeyring(ring, "testring3", t)
	t.Logf("created nested keyring %v named %q", ring.Id(), ring.Name())

	ring, err = OpenKeyring(us, "testring3")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("successfully reopened keyring %v named %q", ring.Id(), ring.Name())
}

func TestUnlinkKeyring(t *testing.T) {
	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}

	nring, err := CreateKeyring(ring, "testring")
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("created keyring %v named %q", nring.Id(), nring.Name())

	err = UnlinkKeyring(nring)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("unlinked keyring %v [%s]", nring.Id(), nring.Name())
}

func TestMoveKey(t *testing.T) {
	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}

	nring, err := CreateKeyring(ring, "testring")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("created keyring %v named %q", nring.Id(), nring.Name())
	defer UnlinkKeyring(nring)

	key, err := ring.Add("move-test", []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("added test key as: %v\n", key.Id())
	defer key.Unlink()

	err = Move(ring, nring, key, false)
	if err != nil {
		t.Fatal(err)
	}

	movedKey, err := nring.Search("move-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("found key in keyring: %v\n", movedKey.Id())
	if movedKey.Id() != key.Id() {
		t.Fatal("IDs don't match\n")
	}
}

func TestUserKeyring(t *testing.T) {
	ring, err := UserKeyring()
	if err != nil {
		t.Fatal(err)
	}
	if ring.Id() == 0 {
		t.Fatal("UserKeyring returned zero id")
	}
	t.Logf("UserKeyring id: %v", ring.Id())
}

func TestThreadKeyring(t *testing.T) {
	ring, err := ThreadKeyring()
	if err != nil {
		t.Fatal(err)
	}
	if ring.Id() == 0 {
		t.Fatal("ThreadKeyring returned zero id")
	}
	t.Logf("ThreadKeyring id: %v", ring.Id())
}

func TestProcessKeyring(t *testing.T) {
	ring, err := ProcessKeyring()
	if err != nil {
		t.Fatal(err)
	}
	if ring.Id() == 0 {
		t.Fatal("ProcessKeyring returned zero id")
	}
	t.Logf("ProcessKeyring id: %v", ring.Id())
}

func TestGroupKeyring(t *testing.T) {
	ring, err := GroupKeyring()
	if err != nil {
		t.Skipf("GroupKeyring not available: %v", err)
	}
	t.Logf("GroupKeyring id: %v", ring.Id())
}

func TestKeyringInfo(t *testing.T) {
	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}
	info, err := ring.Info()
	if err != nil {
		t.Fatal(err)
	}
	if !info.Valid() {
		t.Fatal("session keyring info should be valid")
	}
	t.Logf("session keyring info: type=%s name=%s perm=%s", info.Type, info.Name, info.Perm)
}

func TestLinkAndUnlink(t *testing.T) {
	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}

	nring, err := CreateKeyring(ring, "test-link-ring")
	if err != nil {
		t.Fatal(err)
	}
	defer UnlinkKeyring(nring)

	key, err := ring.Add("test-link-key", []byte("linkme"))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Unlink()

	if err = Link(nring, key); err != nil {
		t.Fatal(err)
	}

	found, err := nring.Search("test-link-key")
	if err != nil {
		t.Fatal(err)
	}
	if found.Id() != key.Id() {
		t.Fatalf("linked key id %v != original %v", found.Id(), key.Id())
	}

	if err = Unlink(nring, key); err != nil {
		t.Fatal(err)
	}
	t.Logf("linked and unlinked key %v to/from keyring %v", key.Id(), nring.Id())
}
