package keyctl

import (
	"errors"
	"testing"
)

func TestStreamWriter(t *testing.T) {
	blk1 := helperRandBlock(1544)

	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}

	w, err := CreateWriter("test1544bytestream", ring)
	if err != nil {
		t.Fatal(err)
	}

	i, err := w.Write(blk1)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}

	if i != len(blk1) {
		t.Fatalf("write mismatch (%d!=%d)", len(blk1), i)
	}
	helperCompareBlock(t, "test1544bytestream", blk1, ring)
	t.Logf("compared %d random block key in common session ring: %v", len(blk1), blk1[:200])
}

func TestStreamWriterUpdate(t *testing.T) {
	blk1 := helperRandBlock(218)

	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}

	ring, err = CreateKeyring(ring, "test")
	if err != nil {
		t.Fatal(err)
	}

	var key *Key

	for key == nil {
		key, err = ring.Search("test218bytestream")
		if err != nil {
			key, err = ring.Add("test218bytestream", []byte{0})
			if err != nil {
				t.Fatal(err)
			}
		}
	}

	w := NewWriter(key)

	i, err := w.Write(blk1)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Flush(); err != nil {
		t.Fatal(err)
	}

	if i != len(blk1) {
		t.Fatalf("write mismatch (%d!=%d)", len(blk1), i)
	}
	helperCompareBlock(t, "test218bytestream", blk1, ring)
	t.Logf("[flushed] compared %d random block key in %q ring: %v", len(blk1), ring.(NamedKeyring).Name(), blk1)
}

func TestStreamWriterFlush(t *testing.T) {
	blk1 := helperRandBlock(218)

	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}

	w, err := CreateWriter("test218bytestream", ring)
	if err != nil {
		t.Fatal(err)
	}

	i, err := w.Write(blk1)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Flush(); err != nil {
		t.Fatal(err)
	}

	if i != len(blk1) {
		t.Fatalf("write mismatch (%d!=%d)", len(blk1), i)
	}
	helperCompareBlock(t, "test218bytestream", blk1, ring)
	t.Logf("[flushed] compared %d random block key in common session ring: %v", len(blk1), blk1)
}

func TestWriterDoubleClose(t *testing.T) {
	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}

	w, err := CreateWriter("test-double-close", ring)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = w.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}

	// First close should succeed
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}

	// Second close must return ErrStreamClosed
	if err = w.Close(); !errors.Is(err, ErrStreamClosed) {
		t.Fatalf("second Close() = %v, want ErrStreamClosed", err)
	}
}

func TestWriterFlushAfterClose(t *testing.T) {
	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}

	w, err := CreateWriter("test-flush-after-close", ring)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = w.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}

	if err = w.Close(); err != nil {
		t.Fatal(err)
	}

	// Flush after close must return ErrStreamClosed
	if err = w.Flush(); !errors.Is(err, ErrStreamClosed) {
		t.Fatalf("Flush() after Close() = %v, want ErrStreamClosed", err)
	}
}
