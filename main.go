package main

import "crypto/x509/pkix"

func main() {
  issuer := pkix.Name {
    Organization: []string{"Magpie"},
    OrganizationalUnit: []string{"VPN servers"},
    CommonName: "MagpieCA",
  }

  var ca CA

  ca.Generate(&issuer, 365, 2048)
}
