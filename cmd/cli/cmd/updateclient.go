/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/willie68/micro-vault/cmd/cli/cmd/cmdutils"
)

// updateClientCmd represents the client command
var updateClientCmd = &cobra.Command{
	Use:   "client",
	Short: "Updates the groups of the named client",
	Long:  `Updates the groups of the named client`,
	RunE: func(cmd *cobra.Command, args []string) error {
		adm, err := cmdutils.AdminClient()
		if err != nil {
			return err
		}
		n, err := cmd.Flags().GetString("name")
		if err != nil {
			return err
		}
		gs, err := cmd.Flags().GetStringSlice("groups")
		cl, err := adm.UpdateClient(n, gs)
		if err != nil {
			return err
		}
		fmt.Println("Name      :", cl.Name)
		fmt.Println("AccessKey :", cl.AccessKey)
		fmt.Println("Secret    :", cl.Secret)
		fmt.Println("Groups    :", cmdutils.Slice2String(cl.Groups))
		fmt.Println("KID       :", cl.KID)
		return nil
	},
}

func init() {
	updateCmd.AddCommand(updateClientCmd)
	updateClientCmd.Flags().StringP("name", "n", "", "Name of the client")
	updateClientCmd.MarkFlagRequired("name")
	updateClientCmd.Flags().StringSliceP("groups", "g", []string{}, "Groups to which the clients belong to.")
}
