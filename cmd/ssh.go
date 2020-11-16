package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"strconv"
	"time"

	"github.com/thomas-maurice/vaultcert/output"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var (
	sshKey        string
	sshEnv        string
	sshRole       string
	sshPrincipals string
)

var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "SSH",
	Long:  ``,
}

var sshSignCmd = &cobra.Command{
	Use:   "sign",
	Short: "SSH Sign",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		c := getClient()

		sshBackend := c.SSH()
		backend, ok := cfg.SSH[sshEnv]
		if !ok {
			logrus.Fatalf("Could not use ssh backend %s, not defined in config", sshEnv)
		}
		sshBackend.MountPoint = backend.Path

		signedCertPath := fmt.Sprintf("%s-%s-cert.pub", sshKey, sshEnv)
		linkPath := fmt.Sprintf("%s-cert.pub", sshKey)

		signedCert, err := ioutil.ReadFile(signedCertPath)
		if err == nil {
			k, _, _, _, err := ssh.ParseAuthorizedKey(signedCert)
			if err != nil {
				logrus.WithError(err).Fatal("Could not parse certificate")
			}
			parsedCert := k.(*ssh.Certificate)
			if int64(parsedCert.ValidBefore)-time.Now().Unix() < 600 {
				logrus.Debug("The certificate expires in less than 10mns, renewing it")
			} else {
				logrus.Debugf(
					"Certificate %s still valid for %v, no need to renew it",
					signedCertPath,
					time.Unix(int64(parsedCert.ValidBefore), 0).Sub(time.Now()),
				)
				if _, err := os.Lstat(linkPath); err == nil {
					err = os.Remove(linkPath)
					if err != nil {
						logrus.WithError(err).Fatalf("Could not remove existing symlink %s", linkPath)
					}
				}
				err = os.Symlink(signedCertPath, linkPath)
				if err != nil {
					logrus.WithError(err).Fatalf("Could not create symlink %s -> %s", linkPath, signedCertPath)
				} else {
					logrus.Debugf("Created symlink %s -> %s", linkPath, signedCertPath)
				}

				output.Write(outputFormat, false, "reusing ssh certificate", map[string]interface{}{
					"env":        sshEnv,
					"backend":    sshBackend,
					"certPath":   signedCertPath,
					"linkPath":   linkPath,
					"serial":     strconv.FormatUint(parsedCert.Serial, 16),
					"role":       sshRole,
					"principals": sshPrincipals,
					"key":        sshKey,
				})
				return
			}
		} else {
			logrus.WithError(err).Debug("Could not check existing cert, getting a new one")
		}

		pubKey, err := ioutil.ReadFile(fmt.Sprintf("%s.pub", sshKey))
		if err != nil {
			logrus.WithError(err).Fatal("Could not load public key")
		}
		result, err := sshBackend.SignKey(sshRole, map[string]interface{}{"public_key": string(pubKey), "valid_principals": sshPrincipals})
		if err != nil {
			logrus.WithError(err).Fatal("Could not sign key")
		}

		serial, ok := result.Data["serial_number"].(string)
		if !ok {
			logrus.Fatal("Could not extract serial number from response")
		}
		certData, ok := result.Data["signed_key"].(string)
		if !ok {
			logrus.Fatal("Could not extract certificate from response")
		}

		err = ioutil.WriteFile(signedCertPath, []byte(certData), 0600)
		if err != nil {
			logrus.WithError(err).Fatal("Could not save the certificate")
		}

		k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certData))
		if err != nil {
			logrus.WithError(err).Fatal("Could not parse certificate")
		}
		parsedCert := k.(*ssh.Certificate)

		logrus.Debugf(
			"Written certificate %s to %s, expires in %v",
			serial,
			signedCertPath,
			time.Unix(int64(parsedCert.ValidBefore), 0).Sub(time.Now()),
		)

		if _, err := os.Lstat(linkPath); err == nil {
			err = os.Remove(linkPath)
			if err != nil {
				logrus.WithError(err).Fatalf("Could not remove existing symlink %s", linkPath)
			}
		}
		err = os.Symlink(signedCertPath, linkPath)
		if err != nil {
			logrus.WithError(err).Fatalf("Could not create symlink %s -> %s", linkPath, signedCertPath)
		} else {
			logrus.Debugf("Created symlink %s -> %s", linkPath, signedCertPath)
		}

		output.Write(outputFormat, false, "issued ssh certificate", map[string]interface{}{
			"env":        sshEnv,
			"backend":    sshBackend,
			"certPath":   signedCertPath,
			"linkPath":   linkPath,
			"serial":     serial,
			"role":       sshRole,
			"principals": sshPrincipals,
			"key":        sshKey,
		})
	},
}

var sshCaCmd = &cobra.Command{
	Use:   "ca",
	Short: "Gets the SSH CA certificate",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		c := getClient()

		backend, ok := cfg.SSH[sshEnv]
		if !ok {
			logrus.Fatalf("Could not use ssh backend %s, not defined in config", sshEnv)
		}

		data, err := c.Logical().Read(backend.Path + "/config/ca")
		if err != nil {
			logrus.WithError(err).Fatal("Could not get the ssh CA")
		}

		fmt.Println(data.Data["public_key"].(string))
	},
}

func initSSHCmd() {
	u, err := user.Current()
	if err != nil {
		logrus.WithError(err).Fatal("Could not get current user")
	}

	sshSignCmd.PersistentFlags().StringVarP(&sshKey, "key", "k", path.Join(u.HomeDir, ".ssh/id_rsa"), "SSH key to sign")
	sshSignCmd.PersistentFlags().StringVarP(&sshEnv, "env", "e", cfg.GetDefaultSSHBackendName(), fmt.Sprintf("SSH environment to sign into (%v)", cfg.GetSSHBackendNames()))
	sshSignCmd.PersistentFlags().StringVarP(&sshRole, "role", "r", "user", "SSH user to sign into")
	sshSignCmd.PersistentFlags().StringVarP(&sshPrincipals, "principals", "p", "*", "SSH principals for which the key is valid")

	sshCaCmd.PersistentFlags().StringVarP(&sshEnv, "env", "e", cfg.GetDefaultSSHBackendName(), fmt.Sprintf("SSH environment to sign into (%v)", cfg.GetSSHBackendNames()))

	sshCmd.AddCommand(sshSignCmd)
	sshCmd.AddCommand(sshCaCmd)

}
