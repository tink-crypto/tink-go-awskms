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

// Package fakeawskms provides a partial fake implementation of the AWS KMS API for testing.
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

// FakeAWSKMS is a fake implementation of the AWS KMS client API for testing.
type FakeAWSKMS struct {
	aeads  map[string]tink.AEAD
	keyIDs []string
}

// serializeContext serializes the context map in a canonical way into a byte array.
func serializeContext(ctx map[string]string) []byte {
	names := make([]string, 0, len(ctx))
	for name := range ctx {
		names = append(names, name)
	}
	sort.Strings(names)
	b := new(bytes.Buffer)
	b.WriteString("{")
	for i, name := range names {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(b, "%q:%q", name, ctx[name])
	}
	b.WriteString("}")
	return b.Bytes()
}

// New returns a new fake AWS KMS client.
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

func (f *FakeAWSKMS) Encrypt(_ context.Context, request *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	a, ok := f.aeads[*request.KeyId]
	if !ok {
		return nil, fmt.Errorf("Unknown keyID: %q not in %q", *request.KeyId, f.keyIDs)
	}
	serializedContext := serializeContext(request.EncryptionContext)
	ciphertext, err := a.Encrypt(request.Plaintext, serializedContext)
	if err != nil {
		return nil, err
	}
	return &kms.EncryptOutput{
		CiphertextBlob: ciphertext,
		KeyId:          request.KeyId,
	}, nil
}

func (f *FakeAWSKMS) Decrypt(_ context.Context, request *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	serializedContext := serializeContext(request.EncryptionContext)
	if request.KeyId != nil {
		a, ok := f.aeads[*request.KeyId]
		if !ok {
			return nil, fmt.Errorf("Unknown keyID: %q not in %q", *request.KeyId, f.keyIDs)
		}
		plaintext, err := a.Decrypt(request.CiphertextBlob, serializedContext)
		if err != nil {
			return nil, fmt.Errorf("Decryption with keyID %q failed", *request.KeyId)
		}
		return &kms.DecryptOutput{
			Plaintext: plaintext,
			KeyId:     request.KeyId,
		}, nil
	}
	// When KeyId is not set, try out all AEADs.
	for keyID, a := range f.aeads {
		plaintext, err := a.Decrypt(request.CiphertextBlob, serializedContext)
		if err == nil {
			return &kms.DecryptOutput{
				Plaintext: plaintext,
				KeyId:     &keyID,
			}, nil
		}
	}
	return nil, errors.New("unable to decrypt message")
}
