package cmd

import (
	"io/ioutil"
	"os/exec"
	"path"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
)

func getClient() *api.Client {
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		logrus.WithError(err).Fatal("Could not get a vault client")
	}

	if vaultToken != "" {
		client.SetToken(vaultToken)
	}

	if vaultAddress != "" {
		client.SetAddress(vaultAddress)
	}

	_, err = client.Auth().Token().LookupSelf()
	if err != nil {
		if isPermissionDenied(err) {
			if cfg.LoginCommand == "" {
				logrus.Error("No Vault log in command specified, cannot attempt relogin")
				logrus.Fatal("Please renew your vault token or check its permissions")
			}
			logrus.WithError(err).Info("Could not log into vault, attempting to relogin")
			reloginIntoVault := exec.Command("sh", "-c", cfg.LoginCommand)
			output, err := reloginIntoVault.CombinedOutput()
			if err != nil {
				logrus.WithError(err).Fatalf("Could not re-log into vault: %s", string(output))
			}

			b, err := ioutil.ReadFile(path.Join(currentUser.HomeDir, ".vault-token"))
			if err == nil {
				client.SetToken(string(b))
			} else {
				logrus.WithError(err).Fatalf("Could not re-log into vault")
			}
			return client
		}
		logrus.WithError(err).Fatal("Failed to self lookup token, might need a renew")
	}

	return client
}

func isPermissionDenied(err error) bool {
	return strings.Contains(err.Error(), "permission denied")
}
