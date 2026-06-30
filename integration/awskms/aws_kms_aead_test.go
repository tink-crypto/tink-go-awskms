// Copyright 2026 Google LLC
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

package awskms

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

// keySwappingKMS is a fake KMS API that returns a configurable KeyId in the
// Decrypt response, simulating a server that decrypts under a different key
// than the one specified in the request. Used to verify that the client-side
// KeyId mismatch check rejects such ciphertexts.
type keySwappingKMS struct {
	kmsiface.KMSAPI
	returnedKeyID string
}

func (k *keySwappingKMS) Decrypt(req *kms.DecryptInput) (*kms.DecryptOutput, error) {
	return &kms.DecryptOutput{
		Plaintext: []byte("plaintext"),
		KeyId:     aws.String(k.returnedKeyID),
	}, nil
}

func TestDecryptRejectsWrongKeyId(t *testing.T) {
	configuredKeyARN := "arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"
	otherKeyARN := "arn:aws:kms:us-east-2:235739564943:key/00000000-0000-0000-0000-000000000000"
	fakeKMS := &keySwappingKMS{returnedKeyID: otherKeyARN}

	a := newAWSAEAD(configuredKeyARN, fakeKMS, AssociatedData)
	_, err := a.Decrypt([]byte("ciphertext"), []byte("ad"))
	if err == nil {
		t.Fatalf("a.Decrypt() err = nil, want error (KeyId mismatch should be rejected)")
	}
	if !strings.Contains(err.Error(), "wrong key id") {
		t.Errorf("a.Decrypt() err = %v, want error containing 'wrong key id'", err)
	}
}

func TestDecryptAcceptsMatchingKeyId(t *testing.T) {
	keyARN := "arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"
	fakeKMS := &keySwappingKMS{returnedKeyID: keyARN}

	a := newAWSAEAD(keyARN, fakeKMS, AssociatedData)
	plaintext, err := a.Decrypt([]byte("ciphertext"), []byte("ad"))
	if err != nil {
		t.Fatalf("a.Decrypt() err = %v, want nil", err)
	}
	if string(plaintext) != "plaintext" {
		t.Errorf("a.Decrypt() = %q, want %q", plaintext, "plaintext")
	}
}

func TestDecryptSkipsCheckForNonArnKeyID(t *testing.T) {
	// Tink-Java disables the KeyId check when the configured key is not in key
	// ARN format (e.g. plain key id, alias/<name>, or alias ARN). This matches
	// that behavior — non-ARN ids are accepted regardless of the returned KeyId.
	tests := []struct {
		name string
		id   string
	}{
		{"plain key id", "3ee50705-5a82-4f5b-9753-05c4f473922f"},
		{"alias name", "alias/test-alias"},
		{"alias ARN (5 segments)", "arn:aws:kms:us-east-2:235739564943:alias/test-alias"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeKMS := &keySwappingKMS{
				returnedKeyID: "arn:aws:kms:us-east-2:235739564943:key/different-key",
			}
			a := newAWSAEAD(test.id, fakeKMS, AssociatedData)
			if _, err := a.Decrypt([]byte("ciphertext"), []byte("ad")); err != nil {
				t.Errorf("a.Decrypt() err = %v, want nil (non-ARN id should skip check)", err)
			}
		})
	}
}

func TestIsKeyArnFormat(t *testing.T) {
	tests := []struct {
		name  string
		id    string
		isArn bool
	}{
		{"valid key ARN", "arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f", true},
		{"valid GovCloud key ARN", "arn:aws-us-gov:kms:us-gov-east-1:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f", true},
		{"alias ARN", "arn:aws:kms:us-east-2:235739564943:alias/my-alias", false},
		{"plain key id", "3ee50705-5a82-4f5b-9753-05c4f473922f", false},
		{"alias name", "alias/my-alias", false},
		{"empty", "", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isKeyArnFormat(test.id); got != test.isArn {
				t.Errorf("isKeyArnFormat(%q) = %v, want %v", test.id, got, test.isArn)
			}
		})
	}
}
