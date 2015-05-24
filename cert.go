package main

import "encoding/pem"
import "crypto/x509"
import "crypto/x509/pkix"
import mathRand "math/rand"
import "crypto/rand"
import "crypto"
import "math/big"
import "time"

func LoadPublicKey(input []byte) *crypto.PublicKey {
  block, _ := pem.Decode(input)
  result, _ := x509.ParsePKIXPublicKey(block.Bytes)
  return result.(*crypto.PublicKey)
}

func Certify(ca *CA, public *crypto.PublicKey, subject pkix.Name, days time.Duration) []byte {
  certificate := x509.Certificate {
    Version: 3,
    PublicKeyAlgorithm: x509.RSA,
    SignatureAlgorithm: x509.SHA256WithRSA,
    PublicKey: public,
    SerialNumber: big.NewInt(mathRand.Int63()),
    Issuer: ca.GetIssuer(),
    Subject: subject,
    NotBefore: time.Now(),
    BasicConstraintsValid: true,
    IsCA: false,
    KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
    ExtKeyUsage: []x509.ExtKeyUsage {x509.ExtKeyUsageServerAuth},
  }
  certificate.NotAfter = certificate.NotBefore.Add(time.Hour * 24 * days)

  der, _ := x509.CreateCertificate(rand.Reader, &certificate, &ca.Certificate, ca.Key.Public(), ca.Key)
  result := pem.EncodeToMemory(&pem.Block {Type: "CERTIFICATE", Bytes: der})
  return result
}
