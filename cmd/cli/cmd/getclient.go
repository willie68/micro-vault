/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/willie68/micro-vault/cmd/cli/cmd/cmdutils"
)

// getClientCmd represents the client command
var getClientCmd = &cobra.Command{
	Use:   "client",
	Short: "getting a single client",
	Long:  `getting all properties of a client`,
	RunE: func(cmd *cobra.Command, args []string) error {
		adm, err := cmdutils.AdminClient()
		if err != nil {
			return err
		}
		n, err := cmd.Flags().GetString("name")
		if err != nil {
			return err
		}
		c, err := adm.Client(n)
		if err != nil {
			return err
		}
		fmt.Printf("Name      : %s\r\n", c.Name)
		fmt.Printf("Acess Key : %s\r\n", c.AccessKey)
		fmt.Printf("Secret    : %s\r\n", c.Secret)
		fmt.Printf("Groups    : %s\r\n", cmdutils.Slice2String(c.Groups))
		fmt.Printf("KID       : %s\r\n", c.KID)
		return nil
	},
}

func init() {
	getCmd.AddCommand(getClientCmd)

	getClientCmd.Flags().StringP("name", "n", "", "Name of the client")
	getClientCmd.MarkFlagRequired("name")
}
