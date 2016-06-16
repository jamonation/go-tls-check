[![Go Report Card](https://goreportcard.com/badge/github.com/jamonation/gotls)](https://goreportcard.com/report/github.com/jamonation/gotls)

This tool is intended to make it easy to parse local PEM encoded RSA keys and x509 certificates, which are commonly used for HTTPS encryption.

Flags are:

```
gotls -h
NAME:
   gotls - Examine local and remote SSL keys and certificates

USAGE:
   gotls [global options] command [command options] [arguments...]

VERSION:
   0.0.2

COMMANDS:
GLOBAL OPTIONS:
   --cert value, -c value	Filesystem path to public .pem file
   --key value, -k value	Filesystem path to private .key file
   --format value, -f value	Output format (text, json) (default: "text")
   --server value, -s value	Remote server name, e.g. golang.org
   --host value			Remote host, e.g. 216.58.220.49 or golang.org
   --port value, -p value	Remote HTTP port, e.g. 8443 (default: 443)
   --insecure			Skip chain & Root CA validation
   --help, -h			show help
   --version, -v		print the version
```

TODOS:

0. REFACTOR (again). Consolidate printing. DRY principle applies.
1. ~~strip all print/formatting from gotls and put into check.go~~
2. ~~remove gotls entirely~~ ignore, was from a temp iteration
3. ~~Add json output for --server/--host case~~
4. Add download cert option for --server/--host case
5. Add enumerate remote TLS ciphers using n (configurable) channels to check remote servers
6. Tests. Tests. Tests. Tests. Tests. All dev should stop until there are tests.
