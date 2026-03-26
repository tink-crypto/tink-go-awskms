// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package fakeawskms provides a partial fake implementation of kmsiface.KMSAPI.
package fakeawskms

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// FakeAWSKMS is a fake implementation of awskms.KMSAPI.
type FakeAWSKMS struct {
	aeads  map[string]tink.AEAD
	keyIDs []string
}

// serializeEncryptionContext serializes the context map in a canonical way into a byte array.
func serializeEncryptionContext(encryptionContext map[string]string) []byte {
	names := make([]string, 0, len(encryptionContext))
	for name := range encryptionContext {
		names = append(names, name)
	}
	sort.Strings(names)
	b := new(bytes.Buffer)
	b.WriteString("{")
	for i, name := range names {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(b, "%q:%q", name, encryptionContext[name])
	}
	b.WriteString("}")
	return b.Bytes()
}

// New returns a new fake AWS KMS API.
func New(validKeyIDs []string) (*FakeAWSKMS, error) {
	aeads := make(map[string]tink.AEAD)
	for _, keyID := range validKeyIDs {
		handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
		if err != nil {
			return nil, err
		}
		a, err := aead.New(handle)
		if err != nil {
			return nil, err
		}
		aeads[keyID] = a
	}
	return &FakeAWSKMS{
		aeads:  aeads,
		keyIDs: validKeyIDs,
	}, nil
}

func (f *FakeAWSKMS) Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a, ok := f.aeads[*params.KeyId]
	if !ok {
		return nil, fmt.Errorf("Unknown keyID: %q not in %q", *params.KeyId, f.keyIDs)
	}
	serializedEncryptionContext := serializeEncryptionContext(params.EncryptionContext)
	ciphertext, err := a.Encrypt(params.Plaintext, serializedEncryptionContext)
	if err != nil {
		return nil, err
	}
	return &kms.EncryptOutput{
		CiphertextBlob: ciphertext,
		KeyId:          params.KeyId,
	}, nil
}

func (f *FakeAWSKMS) Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	serializedEncryptionContext := serializeEncryptionContext(params.EncryptionContext)
	if params.KeyId != nil {
		a, ok := f.aeads[*params.KeyId]
		if !ok {
			return nil, fmt.Errorf("Unknown keyID: %q not in %q", *params.KeyId, f.keyIDs)
		}
		plaintext, err := a.Decrypt(params.CiphertextBlob, serializedEncryptionContext)
		if err != nil {
			return nil, fmt.Errorf("Decryption with keyID %q failed", *params.KeyId)
		}
		return &kms.DecryptOutput{
			Plaintext: plaintext,
			KeyId:     params.KeyId,
		}, nil
	}
	// When KeyId is not set, try out all AEADs.
	for keyID, a := range f.aeads {
		plaintext, err := a.Decrypt(params.CiphertextBlob, serializedEncryptionContext)
		if err == nil {
			return &kms.DecryptOutput{
				Plaintext: plaintext,
				KeyId:     &keyID,
			}, nil
		}
	}
	return nil, errors.New("unable to decrypt message")
}
