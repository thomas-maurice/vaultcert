# vault-cert

Run a devel vault server:
```
docker-compose up
```

Initialise it
```
./init-vault.sh
```

Will create a PKI backend at `v1/pki/pki_intermediate`, get the CA cert:
```
curl http://localhost:8200/v1/dev/pki/pki_intermediate/ca/pem
```

```
# Generate a client cert
./vault-cert -t devroottoken -a http://localhost:8200 cert issue
# Generate a server cert
./vault-cert -t devroottoken -a http://localhost:8200 cert issue --role server
```
