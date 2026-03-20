[![Go Reference](https://pkg.go.dev/badge/github.com/arkhemlol/keyctl.svg)](https://pkg.go.dev/github.com/arkhemlol/keyctl)
[![CI](https://github.com/arkhemlol/keyctl/actions/workflows/ci.yml/badge.svg)](https://github.com/arkhemlol/keyctl/actions/workflows/ci.yml)
[![coverage](https://raw.githubusercontent.com/arkhemlol/keyctl/badges/.badges/master/coverage.svg)](https://github.com/arkhemlol/keyctl/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/arkhemlol/keyctl)](https://goreportcard.com/report/github.com/arkhemlol/keyctl)

# keyctl

A native Go API for the security key management system (aka "keyrings") found in Linux 2.6+

The keyctl interface is nominally provided by three or so Linux-specific syscalls, however it is almost always wrapped
in a library named `libkeyutils.so`.

This package interacts directly with the syscall interface and does not require CGO for linkage to the helper library
provided on most systems.

## Installation

```sh
go get github.com/arkhemlol/keyctl
```

## Usage Examples

### Add and retrieve a key

```go
package main

import (
  "log"
  "github.com/arkhemlol/keyctl"
)

func main() {
  keyring, err := keyctl.SessionKeyring()
  if err != nil {
    log.Fatal(err)
  }

  // Default timeout of 10 seconds for new or updated keys.
  keyring.SetDefaultTimeout(10)

  secureData := []byte{1, 2, 3, 4}
  key, err := keyring.Add("some-data", secureData)
  if err != nil {
    log.Fatal(err)
  }
  log.Printf("created key id %v", key.Id())
}
```

### Search for an existing key

```go
package main

import (
  "log"
  "github.com/arkhemlol/keyctl"
)

func main() {
  keyring, err := keyctl.SessionKeyring()
  if err != nil {
    log.Fatal(err)
  }

  key, err := keyring.Search("some-data")
  if err != nil {
    log.Fatal(err)
  }

  data, err := key.Get()
  if err != nil {
    log.Fatal(err)
  }
  log.Printf("secure data: %v\n", data)
}
```

### Update an existing key

```go
key, err := keyring.Search("some-data")
if err != nil {
  log.Fatal(err)
}

// Set replaces the key's payload and re-arms the TTL if one was set.
if err := key.Set([]byte("new-payload")); err != nil {
  log.Fatal(err)
}
```

### Create and nest keyrings

```go
session, _ := keyctl.SessionKeyring()

// Create a named sub-keyring.
ring, err := keyctl.CreateKeyring(session, "my-app")
if err != nil {
  log.Fatal(err)
}

// Keyrings can be nested arbitrarily.
child, err := keyctl.CreateKeyring(ring, "secrets")
if err != nil {
  log.Fatal(err)
}

// Set a TTL on the whole keyring (and its future children).
if err := keyctl.SetKeyringTTL(ring, 3600); err != nil {
  log.Fatal(err)
}

log.Printf("created keyring %q (id %v) with child %q (id %v)",
  ring.Name(), ring.Id(), child.Name(), child.Id())
```

### Open an existing named keyring

```go
session, _ := keyctl.SessionKeyring()

ring, err := keyctl.OpenKeyring(session, "my-app")
if err != nil {
  log.Fatal(err)
}
log.Printf("opened keyring %q (id %v)", ring.Name(), ring.Id())
```

### Move a key between keyrings

```go
session, _ := keyctl.SessionKeyring()
dest, _ := keyctl.CreateKeyring(session, "destination")

key, _ := session.Add("movable", []byte("data"))

// Move the key from the session keyring to the destination keyring.
// The last argument controls exclusivity (KEYCTL_MOVE_EXCL).
if err := keyctl.Move(session, dest, key, false); err != nil {
  log.Fatal(err)
}
```

### Link and unlink keys across keyrings

```go
session, _ := keyctl.SessionKeyring()
ring, _ := keyctl.CreateKeyring(session, "shared")

key, _ := session.Add("shared-secret", []byte("s3cret"))

// Link the key into another keyring (it now lives in both).
if err := keyctl.Link(ring, key); err != nil {
  log.Fatal(err)
}

// Unlink from the named keyring; the key still exists in the session keyring.
if err := keyctl.Unlink(ring, key); err != nil {
  log.Fatal(err)
}
```

### Set permissions and ownership

```go
key, _ := keyring.Add("restricted", []byte("data"))

// Grant full access to owner and possessor only.
perm := keyctl.PermUserAll | keyctl.PermProcessAll
if err := keyctl.SetPerm(key, perm); err != nil {
  log.Fatal(err)
}

// Change user/group ownership (must have appropriate privileges).
// keyctl.Chown(key, uid)
// keyctl.Chgrp(key, gid)
```

### List keyring contents

```go
session, _ := keyctl.SessionKeyring()

refs, err := keyctl.ListKeyring(session)
if err != nil {
  log.Fatal(err)
}

for _, ref := range refs {
  info, _ := ref.Info()
  log.Printf("id=%d type=%s name=%s perms=%s",
    ref.Id, info.Type, info.Name, info.Perm)
}
```

### Stream I/O with Reader and Writer

```go
// Write key data via an io.Writer.
w, _ := keyctl.CreateWriter("streamed-key", keyring)
w.Write([]byte("hello "))
w.Write([]byte("world"))
w.Close() // or w.Flush() is required to commit the data to the kernel.

// Read key data via an io.Reader.
r, _ := keyctl.OpenReader("streamed-key", keyring)
data, _ := io.ReadAll(r)
log.Printf("read: %s", data)
```

### Available keyring types

```go
keyctl.SessionKeyring()       // Current login session keyring
keyctl.UserSessionKeyring()   // User-session keyring (private to current user)
keyctl.UserKeyring()          // Per-UID keyring
keyctl.ProcessKeyring()       // Per-process keyring
keyctl.ThreadKeyring()        // Per-thread keyring
keyctl.GroupKeyring()         // Group keyring (may not be available)
```

## License

BSD-style license. See [LICENSE](LICENSE) for details.
