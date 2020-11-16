#!/bin/bash

function dkr_vault () {
    docker run --cap-add IPC_LOCK --net=host -e VAULT_ADDR=http://localhost:8200 -e VAULT_TOKEN=devroottoken -it vault:latest $@
}

dkr_vault secrets enable -path=dev/pki/pki_intermediate pki
dkr_vault write dev/pki/pki_intermediate/root/generate/internal common_name="devpki" ttl=8760h
dkr_vault write dev/pki/pki_intermediate/config/urls issuing_certificates="http://127.0.0.1:8200/v1/dev/pki/ca/pem"
dkr_vault write dev/pki/pki_intermediate/roles/server allow_any_name=true server_flag=true client_flag=false max_ttl=72h
dkr_vault write dev/pki/pki_intermediate/roles/client allow_any_name=true server_flag=false client_flag=true max_ttl=72h
