/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/willie68/micro-vault/cmd/cli/cmd/cmdutils"
)

// cacertCmd represents the cacert command
var cacertCmd = &cobra.Command{
	Use:   "cacert",
	Short: "Getting the root certificate of the ca",
	Long:  `Getting the root certificate of the micro-vault certificate authority`,
	RunE: func(cmd *cobra.Command, args []string) error {
		adm, err := cmdutils.AdminClient()
		if err != nil {
			return err
		}
		p, err := adm.GetCACert()
		if err != nil {
			return err
		}
		fmt.Println(p)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(cacertCmd)

	cacertCmd.Flags().String("url", "https://localhost:8443", "insert the url to the mv service")
	cacertCmd.MarkFlagRequired("url")
}
