/*
Copyright 2022 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package certificatebundle

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ValidateAndSanitizePEMBundle strictly validates a given input PEM bundle to confirm it contains
// only valid CERTIFICATE PEM blocks. If successful, returns the validated PEM blocks with any
// comments or extra data stripped.

// This validation is broadly similar to the standard library funtion
// crypto/x509.CertPool.AppendCertsFromPEM - that is, we decode each PEM block at a time and parse
// it as a certificate.

// The difference here is that we want to ensure that the bundle _only_ contains certificates, and
// not just skip over things which aren't certificates.

// If, for example, someone accidentally used a combined cert + private key as an input to a trust
// bundle, we wouldn't want to then distribute the private key in the target.

// In addition, the standard library AppendCertsFromPEM also silently skips PEM blocks with
// non-empty Headers. We error on such PEM blocks, for the same reason as above; headers could
// contain (accidental) private information. They're also non-standard according to
// https://www.rfc-editor.org/rfc/rfc7468

// See also https://github.com/golang/go/blob/5d5ed57b134b7a02259ff070864f753c9e601a18/src/crypto/x509/cert_pool.go#L201-L239
func ValidateAndSanitizePEMBundle(data []byte) ([]byte, error) {
	certificates, err := ValidateAndSplitPEMBundle(data)
	if err != nil {
		return nil, err
	}

	if len(certificates) == 0 {
		return nil, fmt.Errorf("bundle contains no PEM certificates")
	}

	return bytes.TrimSpace(bytes.Join(certificates, nil)), nil
}

// ValidateAndSplitPEMBundle takes a PEM bundle as input, validates it and
// returns the list of certificates as a slice, allowing them to be
// iterated over.
// For details of the validation performed, see the comment for ValidateAndSanitizePEMBundle
func ValidateAndSplitPEMBundle(data []byte) ([][]byte, error) {
	var certificates [][]byte

	for {
		var b *pem.Block
		b, data = pem.Decode(data)

		if b == nil {
			break
		}

		if b.Type != "CERTIFICATE" {
			// only certificates are allowed in a bundle
			return nil, fmt.Errorf("invalid PEM block in bundle: only CERTIFICATE blocks are permitted but found '%s'", b.Type)
		}

		if len(b.Headers) != 0 {
			return nil, fmt.Errorf("invalid PEM block in bundle; blocks are not permitted to have PEM headers")
		}

		_, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			// the presence of an invalid cert (including things which aren't certs)
			// should cause the bundle to be rejected
			return nil, fmt.Errorf("invalid PEM block in bundle; invalid PEM certificate: %w", err)
		}

		certificates = append(certificates, pem.EncodeToMemory(b))
	}

	return certificates, nil
}
