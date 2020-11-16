package cmd

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os/exec"
	"os/user"
	"path"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/thomas-maurice/vaultcert/output"
)

var (
	certEnv         string
	certRole        string
	certCommonName  string
	certAddToChrome bool
)

var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "Manages certificates",
	Long:  ``,
}

func decodePem(certInput []byte) []*x509.Certificate {
	cert := make([]*x509.Certificate, 0)
	var certDERBlock *pem.Block
	for {
		certDERBlock, certInput = pem.Decode(certInput)
		if certDERBlock == nil {
			break
		}
		parsedCert, err := x509.ParseCertificate(certDERBlock.Bytes)
		if err != nil {
			panic(err)
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert = append(cert, parsedCert)
		}
	}
	return cert
}

var certIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issues a certificate",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		c := getClient()
		certCommonName = fmt.Sprintf("vault-cert-%d-%s", time.Now().Unix(), certCommonName)
		backend, ok := cfg.PKI[certEnv]

		if !ok {
			logrus.Fatalf("Could not use pki backend %s, not defined in config", certEnv)
		}

		if previousCert, err := ioutil.ReadFile(path.Join(dataDir, certRole+".crt")); err == nil {
			parsedCert := decodePem(previousCert)
			if err != nil {
				logrus.WithError(err).Warning("could not parse previous cert")
				goto GenCert
			}
			if parsedCert[0].NotAfter.After(time.Now().Add(time.Second * 600)) {
				logrus.Debugf(
					"Certificate %s is still valid for %v, no need to renew",
					parsedCert[0].SerialNumber,
					parsedCert[0].NotAfter.Sub(time.Now()),
				)
				return
			} else {
				logrus.Info("certificate renewal needed")
				logrus.Info(parsedCert[0].Subject)
				logrus.Info(parsedCert[0].NotAfter)
			}
		}

	GenCert:
		certPath := backend.Path + "/issue/"

		result, err := c.Logical().Write(
			certPath+certRole,
			map[string]interface{}{"common_name": certCommonName})
		if err != nil {
			logrus.WithError(err).Fatal("Could not issue certificate")
		}

		serial, ok := result.Data["serial_number"].(string)
		if !ok {
			logrus.Fatal("Could not extract serial number from response")
		}

		certificate, ok := result.Data["certificate"].(string)
		if !ok {
			logrus.Fatal("Could not extract certificate from response")
		}

		privateKey, ok := result.Data["private_key"].(string)
		if !ok {
			logrus.Fatal("Could not extract private key from response")
		}

		caChain, ok := result.Data["issuing_ca"].(string)
		if !ok {
			logrus.Fatal("Could not extract issuing CA from response")
		}

		expirationJSON, ok := result.Data["expiration"].(json.Number)
		if !ok {
			logrus.Fatal("Could not extract expiration from response")
		}

		expiration, err := expirationJSON.Int64()
		if err != nil {
			logrus.WithError(err).Fatalf("Invalid expiration timestamp %v", expirationJSON)
		}

		privateKeyType, ok := result.Data["private_key_type"].(string)
		if !ok {
			logrus.Fatal("Could not extract private key type from response")
		}

		err = ioutil.WriteFile(path.Join(dataDir, certRole+".crt"), []byte(certificate+"\n"+caChain), 0600)
		if err != nil {
			logrus.WithError(err).Fatal("Could not write certificate")
		}

		err = ioutil.WriteFile(path.Join(dataDir, certRole+".key"), []byte(privateKey), 0600)
		if err != nil {
			logrus.WithError(err).Fatal("Could not write private key")
		}

		block, _ := pem.Decode([]byte(certificate))
		if block == nil {
			logrus.Fatal("Could not parse certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			logrus.WithError(err).Fatal("Could not parse certificate")
		}

		var parsedKey crypto.PrivateKey
		switch privateKeyType {
		case "rsa":
			block, _ = pem.Decode([]byte(privateKey))
			if block == nil {
				logrus.Fatal("Could not parse private key")
			}
			parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "ec":
			block, _ = pem.Decode([]byte(privateKey))
			if block == nil {
				logrus.Fatal("Could not parse private key")
			}
			parsedKey, err = x509.ParseECPrivateKey(block.Bytes)
		default:
			logrus.Fatalf("Unknown key type %s", privateKeyType)
		}

		pfxData, err := pkcs12.Encode(rand.Reader, parsedKey, cert, nil, pkcs12.DefaultPassword)
		if err != nil {
			logrus.WithError(err).Fatal("Cannot generate p12 file")
		}

		ioutil.WriteFile(path.Join(dataDir, certRole+".p12"), pfxData, 0600)

		logrus.Debugf(
			"Retrieved certificate %s, key type %s, expires in %s",
			serial,
			privateKeyType,
			time.Unix(int64(expiration), 0).Sub(time.Now()),
		)

		output.Write(outputFormat, false, "retrieved certificate", map[string]interface{}{
			"certPath": path.Join(dataDir, certRole+".crt"),
			"keyPath":  path.Join(dataDir, certRole+".key"),
			"keyType":  privateKeyType,
		})

		if certAddToChrome {
			// Works in 2 steps, first install the certificate, then tjhe key
			installCertCmd := exec.Command("sh", "-c",
				fmt.Sprintf(
					"certutil -n '%s' -t u,u,u -u C -A -i %s/%s.crt -d sql:$HOME/.pki/nssdb",
					certCommonName,
					dataDir,
					certRole,
				),
			)
			output, err := installCertCmd.CombinedOutput()
			if err != nil {
				logrus.Warningf("pk12util output: %s", output)
				logrus.WithError(err).Fatal("Could not add the certificate to Chrome")
			}

			cmd := exec.Command("sh", "-c",
				fmt.Sprintf(
					"pk12util -d sql:$HOME/.pki/nssdb -i %s/%s.p12  -W '%s'",
					dataDir,
					certRole,
					pkcs12.DefaultPassword,
				),
			)
			output, err = cmd.CombinedOutput()
			if err != nil {
				logrus.Warningf("pk12util output: %s", output)
				logrus.WithError(err).Fatal("Could not add the privatekey to Chrome")
			}
			logrus.Debug("Successfully imported the certificate into chrome's store")
		}
	},
}

func initCertCmd() {
	u, err := user.Current()
	if err != nil {
		logrus.WithError(err).Fatal("Could not get current user")
	}

	certIssueCmd.PersistentFlags().StringVarP(&certEnv, "env", "e", cfg.GetDefaultPKIBackendName(), fmt.Sprintf("PKI environment (%v)", cfg.GetPKIBackendNames()))
	certIssueCmd.PersistentFlags().StringVarP(&certRole, "role", "r", "client", "PKI role")
	certIssueCmd.PersistentFlags().StringVarP(&certCommonName, "common-name", "c", u.Username, "Certificate common name")
	certIssueCmd.PersistentFlags().BoolVarP(&certAddToChrome, "add-to-chrome", "b", false, "Adds the certificate to the chrome truststore")

	certCmd.AddCommand(certIssueCmd)
}
