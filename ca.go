package main

import "crypto/rand"
import "crypto/rsa"
import "crypto/x509"
import "crypto/x509/pkix"
import "math/big"
import "time"

func GenerateCA(issuer *pkix.Name, days time.Duration, bits int) (der [] byte, key *rsa.PrivateKey) {
  key, _ = rsa.GenerateKey(rand.Reader, bits)

  cert := x509.Certificate {
    Version: 3,
    PublicKeyAlgorithm: x509.RSA,
    SignatureAlgorithm: x509.SHA256WithRSA,
    PublicKey: key.Public(),
    SerialNumber: big.NewInt(1),
    Issuer: *issuer,
    Subject: *issuer,
    NotBefore: time.Now(),
    BasicConstraintsValid: true,
    IsCA: true,
    KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
  }

  cert.NotAfter = cert.NotBefore.Add(time.Hour * 24 * days)

  der, _ = x509.CreateCertificate(rand.Reader, &cert, &cert, key.Public(), key)
  return
}