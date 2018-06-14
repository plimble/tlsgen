tlsgen
===========

### Installation

```
go get -u github.com/plimble/tlsgen
```

### Command

```
Usage of tlsgen:
  -ca
    	whether this cert should be its own Certificate Authority (default true)
  -duration duration
    	Duration that certificate is valid for (default 8760h0m0s)
  -ecdsa-curve string
    	ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384, P521
  -host string
    	Comma-separated hostnames and IPs to generate a certificate for (default "0.0.0.0")
  -org string
    	organization (default "Acme Co")
  -rsa-bits int
    	Size of RSA key to generate. Ignored if --ecdsa-curve is set (default 2048)
  -start-date string
    	Creation date formatted as Jan 1 15:04:05 2011
```