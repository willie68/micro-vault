/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/willie68/micro-vault/cmd/cli/cmd/cmdutils"
)

// decodeCertificateCmd represents the client command
var decodeCertificateCmd = &cobra.Command{
	Use:   "certificate",
	Short: "Decodes a certificate PEM file into json format",
	Long:  `Decodes a certificate PEM file into json format`,
	RunE: func(cmd *cobra.Command, args []string) error {
		adm, err := cmdutils.AdminClient()
		if err != nil {
			return err
		}
		pf, err := cmd.Flags().GetString("pem")
		if err != nil {
			return err
		}
		pem, err := os.ReadFile(pf)
		if err != nil {
			return err
		}
		cj, err := adm.DecodeCertificate(string(pem))
		if err != nil {
			return err
		}
		js, err := json.Marshal(cj)
		if err != nil {
			return err
		}
		fmt.Println(string(js))
		return nil
	},
}

func init() {
	decodeCmd.AddCommand(decodeCertificateCmd)
	decodeCertificateCmd.Flags().StringP("pem", "p", "", "PEM file")
	decodeCertificateCmd.MarkFlagRequired("pem")
}
