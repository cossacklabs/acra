## Run
From root of repository
```
go run ./benchmarks/acra-translator/grpc/main.go --tls_ca=ca.crt --tls_crt=acra-writer.crt --tls_key=acra-writer.key
```

Flags:
```
  --client_id
    	Client id used in request (default "client")
  --config_file
    	path to config
  --connection_string
    	host:port to AcraTranslator (default "127.0.0.1:9696")
  --data
    	Data sent to encrypt/decrypt (default "some data")
  --dump_config
    	dump config
  --generate_markdown_args_table
    	Generate with yaml config markdown text file with descriptions of all args
  --tls_auth
    	TLS auth type
  --tls_ca
    	TLS CA file (default "ca.crt")
  --tls_crt
    	TLS certificate (default "acra-writer.crt")
  --tls_key
    	TLS private key (default "acra-writer.key")
  --tls_server_sni
    	Server name of AcraTranslator (default "localhost")
```