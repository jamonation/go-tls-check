This tool is intended to make it easy to fetch remote x509 certificates used for HTTPS encryption.

Only the `-s` or `-server` flag is required.

Flags are:

```
  -host string
    	(optional) The hostname or IP of the server to connect to. Use in combination with -k/-noverify to test remote IPs
  -k	Turn off validation. Use with -host and IP addresses for best results
  -noverify
    	Turn off validation. Use with -host and IP addresses for best results
  -p string
    	(default 443) The port on the remote server to check (default "443")
  -s string
    	The DNS name of the server name to check
  -server string
    	The DNS name of the server name to check
```

TODO:

1. This project needs tests. I don't know how to write them in Go. Any help would be appreciated.
1. Refactor all the `fmt.Println` mess into proper switch/case format
