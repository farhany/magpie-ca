package main

import "crypto/x509/pkix"
import "fmt"

func main() {
  issuer := pkix.Name {
    Organization: []string{"Magpie"},
    OrganizationalUnit: []string{"VPN servers"},
    CommonName: "MagpieCA",
  }

  der, key := GenerateCA(&issuer, 365, 2048)
  fmt.Println(der)
  fmt.Println(key)
}
