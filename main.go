package main

import (
	"github.com/thomas-maurice/vaultcert/cmd"
	"github.com/sirupsen/logrus"
)

func main() {
	cmd.InitRootCmd()

	if err := cmd.RootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}
