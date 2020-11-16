all: bin

.PHONY := bin
bin:
	go build -ldflags "-X git.maurice.fr/thomas/vault-cert/cmd.Sha1hash=$(shell git rev-parse HEAD) -X git.maurice.fr/thomas/vault-cert/cmd.BuildTag=$(shell git tag | head -n1) -X git.maurice.fr/thomas/vault-cert/cmd.BuildHost=$(shell hostname) -X git.maurice.fr/thomas/vault-cert/cmd.BuildTime=$(shell date +%Y-%m-%d_%H:%M:%S)"
