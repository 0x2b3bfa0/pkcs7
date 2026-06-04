package pkcs7

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"testing"
)

const pssTestContent = "Hello RSASSA-PSS World"

// pssSignedFixture signs pssTestContent under id-RSASSA-PSS with the given digest
// and returns the DER plus a truststore holding the signing root.
func pssSignedFixture(t *testing.T, digestOID asn1.ObjectIdentifier) ([]byte, *x509.CertPool) {
	t.Helper()
	// SHA256WithRSA selects the 2048-bit test key, large enough for PSS up to SHA-512
	root, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil, x509.SHA256WithRSA, true)
	if err != nil {
		t.Fatalf("cannot generate root cert: %v", err)
	}
	signer, err := createTestCertificateByIssuer("PKCS7 Test PSS Signer", root, x509.SHA256WithRSA, false)
	if err != nil {
		t.Fatalf("cannot generate signer cert: %v", err)
	}
	sd, err := NewSignedData([]byte(pssTestContent))
	if err != nil {
		t.Fatalf("cannot initialize signed data: %v", err)
	}
	sd.SetDigestAlgorithm(digestOID)
	// opt in to RSASSA-PSS
	sd.SetEncryptionAlgorithm(OIDEncryptionAlgorithmRSASSAPSS)
	if err := sd.AddSignerChain(signer.Certificate, *signer.PrivateKey,
		[]*x509.Certificate{root.Certificate}, SignerInfoConfig{}); err != nil {
		t.Fatalf("cannot add signer: %v", err)
	}
	signed, err := sd.Finish()
	if err != nil {
		t.Fatalf("cannot finish signing data: %v", err)
	}
	truststore := x509.NewCertPool()
	truststore.AddCert(root.Certificate)
	return signed, truststore
}

func TestSignAndVerifyRSASSAPSS(t *testing.T) {
	cases := []struct {
		name      string
		digestOID asn1.ObjectIdentifier
		hashName  string
		saltLen   int
	}{
		{"SHA256", OIDDigestAlgorithmSHA256, "SHA-256", 32},
		{"SHA384", OIDDigestAlgorithmSHA384, "SHA-384", 48},
		{"SHA512", OIDDigestAlgorithmSHA512, "SHA-512", 64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signed, truststore := pssSignedFixture(t, tc.digestOID)

			p7, err := Parse(signed)
			if err != nil {
				t.Fatalf("cannot parse signed data: %v", err)
			}
			if len(p7.Signers) != 1 {
				t.Fatalf("expected 1 signer, got %d", len(p7.Signers))
			}
			si := p7.Signers[0]

			// signatureAlgorithm must be id-RSASSA-PSS with parameters
			if !si.DigestEncryptionAlgorithm.Algorithm.Equal(OIDEncryptionAlgorithmRSASSAPSS) {
				t.Fatalf("expected signatureAlgorithm id-RSASSA-PSS, got %v",
					si.DigestEncryptionAlgorithm.Algorithm)
			}
			if len(si.DigestEncryptionAlgorithm.Parameters.FullBytes) == 0 {
				t.Fatal("expected non-empty RSASSA-PSS-params on the signatureAlgorithm")
			}

			// params must decode as the expected hash, MGF1 and saltLength
			hash, err := pssHashFromParams(si.DigestEncryptionAlgorithm.Parameters)
			if err != nil {
				t.Fatalf("cannot decode RSASSA-PSS-params: %v", err)
			}
			if hash.String() != tc.hashName {
				t.Fatalf("expected %s in PSS params, got %v", tc.hashName, hash)
			}
			var params rsaPSSParams
			if _, err := asn1.Unmarshal(si.DigestEncryptionAlgorithm.Parameters.FullBytes, &params); err != nil {
				t.Fatalf("cannot unmarshal RSASSA-PSS-params: %v", err)
			}
			if params.SaltLength != tc.saltLen {
				t.Fatalf("expected saltLength %d, got %d", tc.saltLen, params.SaltLength)
			}
			if !params.MaskGenAlgorithm.Algorithm.Equal(OIDDigestAlgorithmMGF1) {
				t.Fatalf("expected MGF1 mask-gen algorithm, got %v", params.MaskGenAlgorithm.Algorithm)
			}
			// default SID (IssuerAndSerialNumber) is preserved
			if si.IssuerAndSerialNumber.SerialNumber == nil {
				t.Fatal("expected IssuerAndSerialNumber to be populated (default SID)")
			}

			// verify the signature
			if err := p7.VerifyWithChain(truststore); err != nil {
				t.Fatalf("PSS signature verification failed: %v", err)
			}

			// embedded content survives the round-trip
			if !bytes.Equal(p7.Content, []byte(pssTestContent)) {
				t.Fatalf("content mismatch: got %q want %q", p7.Content, pssTestContent)
			}
		})
	}
}

func TestVerifyRSASSAPSSRejectsTamperedSignature(t *testing.T) {
	signed, truststore := pssSignedFixture(t, OIDDigestAlgorithmSHA256)

	// the final DER byte is the last byte of the signature OCTET STRING; flipping
	// it keeps the structure valid but must break signature verification
	tampered := make([]byte, len(signed))
	copy(tampered, signed)
	tampered[len(tampered)-1] ^= 0xff

	p7, err := Parse(tampered)
	if err != nil {
		t.Fatalf("tampered signature should still parse: %v", err)
	}
	if err := p7.VerifyWithChain(truststore); err == nil {
		t.Fatal("expected verification to fail for a tampered signature")
	}
}

// SignWithoutAttr must also honour an RSASSA-PSS selection: the SignerInfo
// carries id-RSASSA-PSS with parameters and a real PSS signature, not the
// parameter-less PSS OID + PKCS#1 v1.5 bytes it would otherwise have emitted.
func TestSignWithoutAttrRSASSAPSS(t *testing.T) {
	root, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil, x509.SHA256WithRSA, true)
	if err != nil {
		t.Fatalf("cannot generate root cert: %v", err)
	}
	signer, err := createTestCertificateByIssuer("PKCS7 Test PSS Signer", root, x509.SHA256WithRSA, false)
	if err != nil {
		t.Fatalf("cannot generate signer cert: %v", err)
	}
	sd, err := NewSignedData([]byte(pssTestContent))
	if err != nil {
		t.Fatalf("cannot initialize signed data: %v", err)
	}
	sd.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	sd.SetEncryptionAlgorithm(OIDEncryptionAlgorithmRSASSAPSS)
	if err := sd.SignWithoutAttr(signer.Certificate, *signer.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("cannot sign: %v", err)
	}
	signed, err := sd.Finish()
	if err != nil {
		t.Fatalf("cannot finish signing data: %v", err)
	}

	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("cannot parse signed data: %v", err)
	}
	si := p7.Signers[0]
	if !si.DigestEncryptionAlgorithm.Algorithm.Equal(OIDEncryptionAlgorithmRSASSAPSS) {
		t.Fatalf("expected signatureAlgorithm id-RSASSA-PSS, got %v", si.DigestEncryptionAlgorithm.Algorithm)
	}
	if len(si.DigestEncryptionAlgorithm.Parameters.FullBytes) == 0 {
		t.Fatal("expected non-empty RSASSA-PSS-params on the signatureAlgorithm")
	}
	if len(si.AuthenticatedAttributes) != 0 {
		t.Fatalf("SignWithoutAttr must not emit signed attributes, got %d", len(si.AuthenticatedAttributes))
	}

	truststore := x509.NewCertPool()
	truststore.AddCert(root.Certificate)
	if err := p7.VerifyWithChain(truststore); err != nil {
		t.Fatalf("PSS signature verification failed: %v", err)
	}
}
