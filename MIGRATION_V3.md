# Migrating to tink-go-awskms v3

v3 upgrades the underlying AWS SDK from v1 to v2, adds `context.Context`
support for encrypt/decrypt operations, and removes long-deprecated factory
functions. Existing `Encrypt`/`Decrypt` calls continue to work without
changes — context support is opt-in.

## Table of contents

- [Module path](#module-path)
- [AWS SDK v1 to v2](#aws-sdk-v1-to-v2)
  - [KMSAPI interface](#kmsapi-interface)
  - [EncryptionContext type](#encryptioncontext-type)
- [Context support](#context-support)
  - [EncryptWithContext and DecryptWithContext](#encryptwithcontext-and-decryptwithcontext)
  - [NewAEADWithContext](#newaeadwithcontext)
- [Removed functions](#removed-functions)
  - [NewClient](#newclient)
  - [NewClientWithKMS](#newclientwithkms)
  - [NewClientWithCredentials](#newclientwithcredentials)
  - [Dropping LegacyAdditionalData](#dropping-legacyadditionaldata)

## Module path

Update your import paths and module dependency:

```
go get github.com/tink-crypto/tink-go-awskms/v3@latest
```

```go
// Before
import "github.com/tink-crypto/tink-go-awskms/v2/integration/awskms"

// After
import "github.com/tink-crypto/tink-go-awskms/v3/integration/awskms"
```

## AWS SDK v1 to v2

The underlying AWS SDK has changed from
[aws-sdk-go](https://github.com/aws/aws-sdk-go) (v1) to
[aws-sdk-go-v2](https://github.com/aws/aws-sdk-go-v2). This is transparent
unless you supply a custom KMS client via `WithKMS()` or interact with KMS
request/response types directly.

### KMSAPI interface

The `kmsiface.KMSAPI` interface from the v1 SDK has been replaced with a
narrow, package-local `KMSAPI` interface. The new methods require
`context.Context` as the first parameter:

```go
// v2: kmsiface.KMSAPI from aws-sdk-go v1
type _ interface {
    Encrypt(input *kms.EncryptInput) (*kms.EncryptOutput, error)
    Decrypt(input *kms.DecryptInput) (*kms.DecryptOutput, error)
    // ... many other methods
}

// v3: package-local KMSAPI, satisfied by *kms.Client from aws-sdk-go-v2
type KMSAPI interface {
    Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
    Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}
```

If you use `WithKMS()` to supply your own client, update it to use
`*kms.Client` from `github.com/aws/aws-sdk-go-v2/service/kms` or any type
satisfying the new `KMSAPI` interface.

### EncryptionContext type

The AWS SDK v2 uses plain `string` values in maps rather than `*string`
pointers:

```go
// v2 (aws-sdk-go v1)
req.EncryptionContext = map[string]*string{"key": aws.String("value")}

// v3 (aws-sdk-go-v2)
req.EncryptionContext = map[string]string{"key": "value"}
```

This only affects code that interacts with `EncryptionContext` directly via a
custom `KMSAPI` implementation.

## Context support

`AWSAEAD` now implements both `tink.AEAD` and `tink.AEADWithContext`. The
existing `Encrypt`/`Decrypt` methods are unchanged — they delegate internally
to the new context-aware methods with `context.Background()`.

### EncryptWithContext and DecryptWithContext

To propagate context (deadlines, cancellation, tracing) through to the AWS KMS
API call, use the new methods:

```go
ciphertext, err := aead.EncryptWithContext(ctx, plaintext, associatedData)
plaintext, err := aead.DecryptWithContext(ctx, ciphertext, associatedData)
```

### NewAEADWithContext

`NewAEADWithContext` is a package-level convenience function that creates a
client and returns a `tink.AEADWithContext` in one step:

```go
aead, err := awskms.NewAEADWithContext(keyURI, awskms.WithKMS(kmsClient))
if err != nil {
    return err
}

ciphertext, err := aead.EncryptWithContext(ctx, plaintext, associatedData)
```

This is equivalent to calling `NewClientWithOptions` followed by `GetAEAD` and
a type assertion, but avoids the assertion by returning `tink.AEADWithContext`
directly.

## Removed functions

Three deprecated factory functions have been removed. Each section below shows
the direct equivalent using `NewClientWithOptions`.

### NewClient

```go
// Before (v2)
client, err := awskms.NewClient(keyURI)

// After (v3) — direct equivalent
client, err := awskms.NewClientWithOptions(keyURI,
    awskms.WithEncryptionContextName(awskms.LegacyAdditionalData),
)
```

### NewClientWithKMS

```go
// Before (v2)
client, err := awskms.NewClientWithKMS(keyURI, kmsClient)

// After (v3) — direct equivalent
client, err := awskms.NewClientWithOptions(keyURI,
    awskms.WithKMS(kmsClient),
    awskms.WithEncryptionContextName(awskms.LegacyAdditionalData),
)
```

### NewClientWithCredentials

```go
// Before (v2)
client, err := awskms.NewClientWithCredentials(keyURI, "/path/to/credentials.csv")

// After (v3) — direct equivalent
client, err := awskms.NewClientWithOptions(keyURI,
    awskms.WithCredentialPath("/path/to/credentials.csv"),
    awskms.WithEncryptionContextName(awskms.LegacyAdditionalData),
)
```

### Dropping LegacyAdditionalData

The direct equivalents above include `WithEncryptionContextName(awskms.LegacyAdditionalData)` because the removed functions defaulted to `"additionalData"` as the encryption context name, while `NewClientWithOptions` defaults to `"associatedData"` (compatible with Tink AWS KMS extensions in other languages).

You can drop `WithEncryptionContextName` if:

- You have no existing ciphertexts produced by `NewClient`, `NewClientWithKMS`,
  or `NewClientWithCredentials`, **or**
- You re-encrypt all existing data after migrating.
