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
//
////////////////////////////////////////////////////////////////////////////////

// Package fakeawskms provides a partial fake implementation of kmsiface.KMSAPI.
package fakeawskms

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"

	kmsv2 "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

type fakeAWSKMS struct {
	kmsiface.KMSAPI
	aeads  map[string]tink.AEAD
	keyIDs []string
}

// serializeContext serializes the context map in a canonical way into a byte array.
func serializeContext(context map[string]*string) []byte {
	names := make([]string, 0, len(context))
	for name := range context {
		names = append(names, name)
	}
	sort.Strings(names)
	b := new(bytes.Buffer)
	b.WriteString("{")
	for i, name := range names {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(b, "%q:%q", name, *context[name])
	}
	b.WriteString("}")
	return b.Bytes()
}

// New returns a new fake AWS KMS API.
func New(validKeyIDs []string) (kmsiface.KMSAPI, error) {
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
	return &fakeAWSKMS{
		aeads:  aeads,
		keyIDs: validKeyIDs,
	}, nil
}

func (f *fakeAWSKMS) Encrypt(request *kms.EncryptInput) (*kms.EncryptOutput, error) {
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

func (f *fakeAWSKMS) Decrypt(request *kms.DecryptInput) (*kms.DecryptOutput, error) {
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

type FakeAWSKMSV2 struct {
	v1 kmsiface.KMSAPI
}

// NewV2 returns a new fake AWS KMS V2 API.
func NewV2(validKeyIDs []string) (*FakeAWSKMSV2, error) {
	v1, err := New(validKeyIDs)
	if err != nil {
		return nil, err
	}
	return &FakeAWSKMSV2{
		v1: v1,
	}, nil
}
func (f FakeAWSKMSV2) Encrypt(_ context.Context, params *kmsv2.EncryptInput, _ ...func(*kmsv2.Options)) (*kmsv2.EncryptOutput, error) {
	encContext := make(map[string]*string)
	for k, v := range params.EncryptionContext {
		encContext[k] = &v
	}

	res, err := f.v1.Encrypt(&kms.EncryptInput{
		KeyId:             params.KeyId,
		Plaintext:         params.Plaintext,
		EncryptionContext: encContext,
	})
	if err != nil {
		return nil, err
	}
	return &kmsv2.EncryptOutput{
		CiphertextBlob: res.CiphertextBlob,
		KeyId:          res.KeyId,
	}, nil
}

func (f FakeAWSKMSV2) Decrypt(_ context.Context, params *kmsv2.DecryptInput, _ ...func(*kmsv2.Options)) (*kmsv2.DecryptOutput, error) {
	encContext := make(map[string]*string)
	for k, v := range params.EncryptionContext {
		encContext[k] = &v
	}

	res, err := f.v1.Decrypt(&kms.DecryptInput{
		KeyId:             params.KeyId,
		CiphertextBlob:    params.CiphertextBlob,
		EncryptionContext: encContext,
	})
	if err != nil {
		return nil, err
	}
	return &kmsv2.DecryptOutput{
		Plaintext: res.Plaintext,
		KeyId:     res.KeyId,
	}, nil
}
