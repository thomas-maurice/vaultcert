package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/thomas-maurice/vaultcert/config"
)

var (
	// Build tags
	Sha1hash  string
	BuildHost string
	BuildTime string
	BuildTag  string

	vaultAddress string
	vaultToken   string
	cfg          *config.Config
	dataDir      string
	debug        bool
	currentUser  *user.User
	outputFormat string
)

const (
	// DataDirName is the datadir in the user's home
	DataDirName = ".vault-cert"
	// VaultServerAddressVar is the environment variable containing the vault server address
	VaultServerAddressVar = "VAULT_ADDR"
)

// RootCmd root command
var RootCmd = &cobra.Command{
	Use:   "vault-cert",
	Short: "vault-cert",
	Run: func(cmd *cobra.Command, args []string) {
	},
}

// VersionCmd prints the version string
var VersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Git Hash: %s\nBuild Host: %s\nBuild Time: %s\nBuild Tag: %s\n", Sha1hash, BuildHost, BuildTime, BuildTag)
	},
}

// InitRootCmd initializes the root command, the subcommands,
// the global configuration variables and everything else
func InitRootCmd() {
	var err error

	currentUser, err = user.Current()
	if err != nil {
		logrus.WithError(err).Fatal("Could not get current user")
	}

	var defaultVaultToken string

	b, err := ioutil.ReadFile(path.Join(currentUser.HomeDir, ".vault-token"))
	if err == nil {
		defaultVaultToken = string(b)
	}

	cfg, err = config.GetConfig(path.Join(currentUser.HomeDir, ".vault-cert.yaml"))
	if err != nil {
		logrus.WithError(err).Error("Could not load the config file")
		logrus.Fatal("Please create a config file")
	}

	initSSHCmd()
	initCertCmd()

	RootCmd.PersistentFlags().StringVarP(&vaultAddress, "address", "a", os.Getenv(VaultServerAddressVar), "Vault address")
	RootCmd.PersistentFlags().StringVarP(&vaultToken, "token", "t", defaultVaultToken, "Vault token")
	RootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Run in debug mode")
	RootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "json", "Output format for the results")

	RootCmd.AddCommand(VersionCmd)
	RootCmd.AddCommand(sshCmd)
	RootCmd.AddCommand(certCmd)
}
