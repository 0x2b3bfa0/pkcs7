package pkcs7

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// rsaPSSParams is RSASSA-PSS-params (RFC 4055 §3.1). trailerField is omitted: its
// only legal value is the ASN.1 DEFAULT.
type rsaPSSParams struct {
	HashAlgorithm    pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
	MaskGenAlgorithm pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
	SaltLength       int                      `asn1:"explicit,tag:2"`
}

// pssParametersForHash builds DER RSASSA-PSS-params for h: MGF1 over the same
// hash, salt length equal to the hash size, and digest AlgorithmIdentifiers with
// an explicit NULL parameter (RFC 4055 §2.1).
func pssParametersForHash(h crypto.Hash) ([]byte, error) {
	digestOID, err := getOIDForHash(h)
	if err != nil {
		return nil, err
	}
	digestAI := pkix.AlgorithmIdentifier{
		Algorithm:  digestOID,
		Parameters: asn1.NullRawValue,
	}
	mgf1ParamDER, err := asn1.Marshal(digestAI)
	if err != nil {
		return nil, err
	}
	mgf1AI := pkix.AlgorithmIdentifier{
		Algorithm:  OIDDigestAlgorithmMGF1,
		Parameters: asn1.RawValue{FullBytes: mgf1ParamDER},
	}
	params := rsaPSSParams{
		HashAlgorithm:    digestAI,
		MaskGenAlgorithm: mgf1AI,
		SaltLength:       h.Size(),
	}
	return asn1.Marshal(params)
}

// PSSAlgorithmIdentifier returns the id-RSASSA-PSS AlgorithmIdentifier for h. It
// is exported so callers can build a matching RFC 6211 CMSAlgorithmProtection.
func PSSAlgorithmIdentifier(h crypto.Hash) (pkix.AlgorithmIdentifier, error) {
	paramDER, err := pssParametersForHash(h)
	if err != nil {
		return pkix.AlgorithmIdentifier{}, err
	}
	return pkix.AlgorithmIdentifier{
		Algorithm:  OIDEncryptionAlgorithmRSASSAPSS,
		Parameters: asn1.RawValue{FullBytes: paramDER},
	}, nil
}

func pssSignatureAlgorithmForHash(h crypto.Hash) (x509.SignatureAlgorithm, error) {
	switch h {
	case crypto.SHA256:
		return x509.SHA256WithRSAPSS, nil
	case crypto.SHA384:
		return x509.SHA384WithRSAPSS, nil
	case crypto.SHA512:
		return x509.SHA512WithRSAPSS, nil
	}
	return x509.UnknownSignatureAlgorithm, fmt.Errorf("pkcs7: unsupported hash %v for RSASSA-PSS", h)
}

// pssHashFromParams returns the hash named in the RSASSA-PSS-params. The
// parameters are required; the all-default (SHA-1) profile is not supported.
func pssHashFromParams(params asn1.RawValue) (crypto.Hash, error) {
	if len(params.FullBytes) == 0 || params.Tag == asn1.TagNull {
		return 0, fmt.Errorf("pkcs7: RSASSA-PSS parameters are required")
	}
	var p rsaPSSParams
	if _, err := asn1.Unmarshal(params.FullBytes, &p); err != nil {
		return 0, err
	}
	return getHashForOID(p.HashAlgorithm.Algorithm)
}

func pssSignOptions(h crypto.Hash) crypto.SignerOpts {
	return &rsa.PSSOptions{Hash: h, SaltLength: rsa.PSSSaltLengthEqualsHash}
}
