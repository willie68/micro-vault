/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/willie68/micro-vault/cmd/cli/cmd/cmdutils"
)

// getCertificateCmd represents the certificate command
var getCertificateCmd = &cobra.Command{
	Use:   "certificate",
	Short: "get a signed certificate from the mv ca",
	Long:  `get a signed certificate from the mv ca`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := cmdutils.Client()
		if err != nil {
			return err
		}
		p, err := cli.Certificate(template x509.CertificateRequest)
		if err != nil {
			return err
		}
		fmt.Println(p)
		return nil
	},
}

func init() {
	getCmd.AddCommand(getCertificateCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// certificateCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// certificateCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
