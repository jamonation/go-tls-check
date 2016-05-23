This tool is intended to make it easy to parse local PEM encoded RSA keys and x509 certificates, which are commonly used for HTTPS encryption.

Flags are:

```
./checkfile -h                      
NAME:
   gotls - Examine local and (soon) remote SSL keys and certificates

USAGE:
   checkfile [global options] command [command options] [arguments...]

VERSION:
   0.0.0

COMMANDS:
GLOBAL OPTIONS:
   --cert value, -c value	Filesystem path to public .pem file
   --key value, -k value	Filesystem path to private .key file
   --format value, -f value	Output format (text, json) (default: "text")
   --server value, -s value	Remote server name, e.g. golang.org
   --host value			Remote host, e.g. 216.58.220.49 or golang.org
   --port value, -p value	Remote HTTP port, e.g. 8443 (default: 443)
   --help, -h			show help
   --version, -v		print the version
```
