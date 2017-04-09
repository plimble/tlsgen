package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "tlsgen"
	app.Usage = "Generates web server TLS certificates"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "org",
			Value: "",
			Usage: "Organization name",
		},
		cli.IntFlag{
			Name:  "days",
			Value: 365,
			Usage: "Expired in day",
		},
		cli.StringSliceFlag{
			Name:  "host",
			Value: &cli.StringSlice{},
			Usage: "Server Host",
		},
	}
	app.Action = func(c *cli.Context) {
		org := c.String("org")
		if org == "" {
			logrus.Fatal("org shoule not be empty")
		}
		days := c.Int("days")
		if days == 0 {
			logrus.Fatal("days must not be 0")
		}
		hosts := c.StringSlice("host")
		if len(hosts) == 0 {
			logrus.Fatal("host shoule not be empty")
		}
		GenerateCACertificate("ca.crt", "ca.key", hosts, org, days, 2048)
	}

	app.Run(os.Args)
}

func newCertificate(org string, days int) (*x509.Certificate, error) {
	now := time.Now()
	// need to set notBefore slightly in the past to account for time
	// skew in the VMs otherwise the certs sometimes are not yet valid
	notBefore := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute()-5, 0, 0, time.Local)
	notAfter := notBefore.Add(time.Hour * 24 * time.Duration(days))

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}, nil

}

// GenerateCACertificate generates a new certificate authority from the specified org
// and bit size and stores the resulting certificate and key file
// in the arguments.
func GenerateCACertificate(certFile, keyFile string, hosts []string, org string, days, bits int) error {
	template, err := newCertificate(org, days)
	if err != nil {
		return err
	}

	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign
	if len(hosts) == 1 && hosts[0] == "" {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		template.KeyUsage = x509.KeyUsageDigitalSignature
	} else { // server
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		for _, h := range hosts {
			if ip := net.ParseIP(h); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)

			} else {
				template.DNSNames = append(template.DNSNames, h)
			}
		}
	}

	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err

	}

	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	return nil
}
