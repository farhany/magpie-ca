package main

import "crypto/rand"
import "crypto/rsa"
import "crypto/x509"
import "crypto/x509/pkix"
import "math/big"
import "time"
import "encoding/pem"
import "io/ioutil"
import "os"

type CA struct {
  Certificate [] byte
  Key *rsa.PrivateKey
}

func (self *CA) Generate(issuer *pkix.Name, days time.Duration, bits int) {
  self.Key, _ = rsa.GenerateKey(rand.Reader, bits)

  cert := x509.Certificate {
    Version: 3,
    PublicKeyAlgorithm: x509.RSA,
    SignatureAlgorithm: x509.SHA256WithRSA,
    PublicKey: self.Key.Public(),
    SerialNumber: big.NewInt(1),
    Issuer: *issuer,
    Subject: *issuer,
    NotBefore: time.Now(),
    BasicConstraintsValid: true,
    IsCA: true,
    KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
  }

  cert.NotAfter = cert.NotBefore.Add(time.Hour * 24 * days)

  self.Certificate, _ = x509.CreateCertificate(rand.Reader, &cert, &cert, self.Key.Public(), self.Key)
  return
}

func (self *CA) PublicPEM() []byte {
  publicBytes, _ := x509.MarshalPKIXPublicKey(self.Key.Public())
  return pem.EncodeToMemory(&pem.Block {Type: "RSA PUBLIC KEY", Bytes: publicBytes})
}

func (self *CA) PrivatePEM() []byte {
  privateBytes := x509.MarshalPKCS1PrivateKey(self.Key)
  return pem.EncodeToMemory(&pem.Block {Type: "RSA PRIVATE KEY", Bytes: privateBytes})
}

func (self *CA) LoadPrivatePEM(input []byte) {
  self.Key, _ = x509.ParsePKCS1PrivateKey(input)
}

func (self *CA) CertPEM() []byte {
  return pem.EncodeToMemory(&pem.Block {Type: "CERTIFICATE", Bytes: self.Certificate})
}

func (self *CA) LoadCertPEM(input []byte) {
  self.Certificate = input
}

func (self *CA) Save() {
  ioutil.WriteFile("private.pem", self.PrivatePEM(), os.ModePerm)
  ioutil.WriteFile("cert.pem", self.CertPEM(), os.ModePerm)
}

func (self *CA) Load() {
  privateInput, _ := ioutil.ReadFile("private.pem")
  self.LoadPrivatePEM(privateInput)

  certInput, _ := ioutil.ReadFile("cert.pem")
  self.LoadCertPEM(certInput)
}
