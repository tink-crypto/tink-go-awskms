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

package fakeawskms

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/aws"
)

const validKeyID = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
const validKeyID2 = "arn:aws:kms:us-west-2:123:key/different"

func TestEncyptDecryptWithValidKeyId(t *testing.T) {
	fakeKMS, err := New([]string{validKeyID})
	if err != nil {
		t.Fatalf("New() err = %s, want nil", err)
	}

	plaintext := []byte("plaintext")
	contextValue := "contextValue"
	encryptionContext := map[string]string{"contextName": contextValue}

	encRequest := &kms.EncryptInput{
		KeyId:             aws.String(validKeyID),
		Plaintext:         plaintext,
		EncryptionContext: encryptionContext,
	}

	encResponse, err := fakeKMS.Encrypt(t.Context(), encRequest)
	if err != nil {
		t.Fatalf("fakeKMS.Encrypt(t.Context(), encRequest) err = %s, want nil", err)
	}

	ciphertext := encResponse.CiphertextBlob

	decRequest := &kms.DecryptInput{
		KeyId:             aws.String(validKeyID),
		CiphertextBlob:    ciphertext,
		EncryptionContext: encryptionContext,
	}
	decResponse, err := fakeKMS.Decrypt(t.Context(), decRequest)
	if err != nil {
		t.Fatalf("fakeKMS.Decrypt(t.Context(), decRequest) err = %s, want nil", err)
	}
	if !bytes.Equal(decResponse.Plaintext, plaintext) {
		t.Fatalf("decResponse.Plaintext = %q, want %q", decResponse.Plaintext, plaintext)
	}
	if strings.Compare(*decResponse.KeyId, validKeyID) != 0 {
		t.Fatalf("decResponse.KeyId = %q, want %q", *decResponse.KeyId, validKeyID)
	}

	// decrypt with a different context should fail
	otherContextValue := "otherContextValue"
	otherEncryptionContext := map[string]string{"contextName": otherContextValue}
	otherDecRequest := &kms.DecryptInput{
		KeyId:             aws.String(validKeyID),
		CiphertextBlob:    ciphertext,
		EncryptionContext: otherEncryptionContext,
	}
	if _, err := fakeKMS.Decrypt(t.Context(), otherDecRequest); err == nil {
		t.Fatal("fakeKMS.Decrypt(t.Context(), otherDecRequest) err = nil, want not nil")
	}
}

func TestEncyptWithUnknownKeyID(t *testing.T) {
	fakeKMS, err := New([]string{validKeyID})
	if err != nil {
		t.Fatalf("New() err = %s, want nil", err)
	}

	plaintext := []byte("plaintext")
	contextValue := "contextValue"
	encryptionContext := map[string]string{"contextName": contextValue}

	encRequestWithUnknownKeyID := &kms.EncryptInput{
		KeyId:             aws.String(validKeyID2),
		Plaintext:         plaintext,
		EncryptionContext: encryptionContext,
	}

	if _, err := fakeKMS.Encrypt(t.Context(), encRequestWithUnknownKeyID); err == nil {
		t.Fatal("fakeKMS.Encrypt(encRequestWithvalidKeyID2) err = nil, want not nil")
	}
}

func TestDecryptWithInvalidCiphertext(t *testing.T) {
	fakeKMS, err := New([]string{validKeyID})
	if err != nil {
		t.Fatalf("New() err = %s, want nil", err)
	}

	invalidCiphertext := []byte("plaintext")
	contextValue := "contextValue"
	encryptionContext := map[string]string{"contextName": contextValue}

	decRequest := &kms.DecryptInput{
		CiphertextBlob:    invalidCiphertext,
		EncryptionContext: encryptionContext,
	}

	if _, err := fakeKMS.Decrypt(t.Context(), decRequest); err == nil {
		t.Fatal("fakeKMS.Decrypt(t.Context(), decRequest) err = nil, want not nil")
	}
}

func TestDecryptWithUnknownKeyId(t *testing.T) {
	fakeKMS, err := New([]string{validKeyID})
	if err != nil {
		t.Fatalf("New() err = %s, want nil", err)
	}

	ciphertext := []byte("invalidCiphertext")
	contextValue := "contextValue"
	encryptionContext := map[string]string{"contextName": contextValue}

	decRequest := &kms.DecryptInput{
		KeyId:             aws.String(validKeyID2),
		CiphertextBlob:    ciphertext,
		EncryptionContext: encryptionContext,
	}

	if _, err := fakeKMS.Decrypt(t.Context(), decRequest); err == nil {
		t.Fatal("fakeKMS.Decrypt(t.Context(), decRequest) err = nil, want not nil")
	}
}

func TestDecryptWithWrongKeyId(t *testing.T) {
	fakeKMS, err := New([]string{validKeyID, validKeyID2})
	if err != nil {
		t.Fatalf("New() err = %s, want nil", err)
	}

	plaintext := []byte("plaintext")
	contextValue := "contextValue"
	encryptionContext := map[string]string{"contextName": contextValue}

	encRequest := &kms.EncryptInput{
		KeyId:             aws.String(validKeyID),
		Plaintext:         plaintext,
		EncryptionContext: encryptionContext,
	}

	encResponse, err := fakeKMS.Encrypt(t.Context(), encRequest)
	if err != nil {
		t.Fatalf("fakeKMS.Encrypt(t.Context(), encRequest) err = %s, want nil", err)
	}

	ciphertext := encResponse.CiphertextBlob

	decRequest := &kms.DecryptInput{
		KeyId:             aws.String(validKeyID2), // wrong key id
		CiphertextBlob:    ciphertext,
		EncryptionContext: encryptionContext,
	}
	if _, err := fakeKMS.Decrypt(t.Context(), decRequest); err == nil {
		t.Fatal("fakeKMS.Decrypt(t.Context(), decRequest) err = nil, want not nil")
	}
}

func TestDecryptWithoutKeyId(t *testing.T) {
	// setting the keyId in DecryptInput is not required, see
	// https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/kms#DecryptInput

	fakeKMS, err := New([]string{validKeyID, validKeyID2})
	if err != nil {
		t.Fatalf("New() err = %s, want nil", err)
	}

	plaintext := []byte("plaintext")
	plaintext2 := []byte("plaintext2")
	contextValue := "contextValue"
	encryptionContext := map[string]string{"contextName": contextValue}

	encRequest := &kms.EncryptInput{
		KeyId:             aws.String(validKeyID),
		Plaintext:         plaintext,
		EncryptionContext: encryptionContext,
	}
	encResponse, err := fakeKMS.Encrypt(t.Context(), encRequest)
	if err != nil {
		t.Fatalf("fakeKMS.Encrypt(t.Context(), encRequest) err = %s, want nil", err)
	}
	if strings.Compare(*encResponse.KeyId, validKeyID) != 0 {
		t.Fatalf("encResponse.KeyId = %q, want %q", *encResponse.KeyId, validKeyID)
	}

	encRequest2 := &kms.EncryptInput{
		KeyId:             aws.String(validKeyID2),
		Plaintext:         plaintext2,
		EncryptionContext: encryptionContext,
	}
	encResponse2, err := fakeKMS.Encrypt(t.Context(), encRequest2)
	if err != nil {
		t.Fatalf("fakeKMS.Encrypt(t.Context(), encRequest2) err = %s, want nil", err)
	}
	if strings.Compare(*encResponse2.KeyId, validKeyID2) != 0 {
		t.Fatalf("encResponse2.KeyId = %q, want %q", *encResponse2.KeyId, validKeyID2)
	}

	decRequest := &kms.DecryptInput{
		// KeyId is not set
		CiphertextBlob:    encResponse.CiphertextBlob,
		EncryptionContext: encryptionContext,
	}
	decResponse, err := fakeKMS.Decrypt(t.Context(), decRequest)
	if err != nil {
		t.Fatalf("fakeKMS.Decrypt(t.Context(), decRequest) err = %s, want nil", err)
	}
	if !bytes.Equal(decResponse.Plaintext, plaintext) {
		t.Fatalf("decResponse.Plaintext = %q, want %q", decResponse.Plaintext, plaintext)
	}
	if strings.Compare(*decResponse.KeyId, validKeyID) != 0 {
		t.Fatalf("decResponse.KeyId = %q, want %q", *decResponse.KeyId, validKeyID)
	}

	decRequest2 := &kms.DecryptInput{
		// KeyId is not set
		CiphertextBlob:    encResponse2.CiphertextBlob,
		EncryptionContext: encryptionContext,
	}
	decResponse2, err := fakeKMS.Decrypt(t.Context(), decRequest2)
	if err != nil {
		t.Fatalf("fakeKMS.Decrypt(decRequest2) err = %s, want nil", err)
	}
	if !bytes.Equal(decResponse2.Plaintext, plaintext2) {
		t.Fatalf("decResponse.Plaintext = %q, want %q", decResponse.Plaintext, plaintext2)
	}
	if strings.Compare(*decResponse2.KeyId, validKeyID2) != 0 {
		t.Fatalf("decResponse2.KeyId = %q, want %q", *decResponse2.KeyId, validKeyID2)
	}
}

func TestEncryptDecrypt_withCanceledContext_fails(t *testing.T) {
	fakeKMS, err := New([]string{validKeyID})
	if err != nil {
		t.Fatalf("New() err = %s, want nil", err)
	}

	plaintext := []byte("plaintext")
	contextValue := "contextValue"
	encryptionContext := map[string]string{"contextName": contextValue}

	// create valid encryption request
	encRequest := &kms.EncryptInput{
		KeyId:             aws.String(validKeyID),
		Plaintext:         plaintext,
		EncryptionContext: encryptionContext,
	}
	// create valid decryption request
	encResponse, err := fakeKMS.Encrypt(t.Context(), encRequest)
	if err != nil {
		t.Fatalf("fakeKMS.Encrypt(t.Context(), encRequest) err = %s, want nil", err)
	}
	ciphertext := encResponse.CiphertextBlob
	decRequest := &kms.DecryptInput{
		KeyId:             aws.String(validKeyID),
		CiphertextBlob:    ciphertext,
		EncryptionContext: encryptionContext,
	}

	ctx := t.Context()
	canceledCtx, cancel := context.WithCancelCause(ctx)
	causeErr := errors.New("cause error message")
	cancel(causeErr)

	_, err = fakeKMS.Encrypt(canceledCtx, encRequest)
	if err == nil {
		t.Fatalf("fakeKMS.Encrypt(canceledCtx, encRequest) err = nil, want error")
	}
	_, err = fakeKMS.Decrypt(canceledCtx, decRequest)
	if err == nil {
		t.Fatalf("fakeKMS.Decrypt(canceledCtx, decRequest) err = nil, want error")
	}
}

func TestSerializeEncryptionContext(t *testing.T) {
	uvw := "uvw"
	xyz := "xyz"
	rst := "rst"
	encryptionContext := map[string]string{"def": uvw, "abc": xyz, "ghi": rst}

	got := string(serializeEncryptionContext(encryptionContext))
	want := "{\"abc\":\"xyz\",\"def\":\"uvw\",\"ghi\":\"rst\"}"
	if got != want {
		t.Fatalf("serializeEncryptionContext(context) = %s, want %s", got, want)
	}

	gotEscaped := string(serializeEncryptionContext(map[string]string{"a\"b": xyz}))
	wantEscaped := "{\"a\\\"b\":\"xyz\"}"
	if gotEscaped != wantEscaped {
		t.Fatalf("serializeEncryptionContext(context) = %s, want %s", gotEscaped, wantEscaped)
	}

	gotEmpty := string(serializeEncryptionContext(map[string]string{}))
	if gotEmpty != "{}" {
		t.Fatalf("serializeEncryptionContext(context) = %s, want %s", gotEmpty, "{}")
	}
}
