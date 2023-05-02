/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/willie68/micro-vault/cmd/cli/cmd/cmdutils"
)

// groupCmd represents the group command
var getGroupCmd = &cobra.Command{
	Use:   "group",
	Short: "Getting a single group",
	Long:  `Getting all properties of a single group`,
	RunE: func(cmd *cobra.Command, args []string) error {
		adm, err := cmdutils.AdminClient()
		if err != nil {
			return err
		}
		n, err := cmd.Flags().GetString("name")
		if err != nil {
			return err
		}
		g, err := adm.Group(n)
		if err != nil {
			return err
		}
		fmt.Printf("Name      : %s\r\n", g.Name)
		fmt.Printf("is Client : %t\r\n", g.IsClient)
		fmt.Printf("Label      : %s\r\n", cmdutils.Labels2String(g.Label))
		return nil
	},
}

func init() {
	getCmd.AddCommand(getGroupCmd)

	getGroupCmd.Flags().StringP("name", "n", "", "Name of the group")
	getGroupCmd.MarkFlagRequired("name")
}
