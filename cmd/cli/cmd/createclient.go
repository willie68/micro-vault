/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/willie68/micro-vault/cmd/cli/cmd/cmdutils"
)

// createClientCmd represents the client command
var createClientCmd = &cobra.Command{
	Use:   "client",
	Short: "create a new client to the mv instance",
	Long: `With this command you can create a new client in the mv instance and add some group information to it. 
After creation you will get an accesskey and the secret of this client. 
Attention: The secret will never be shown again and nowhere stored on the mv instance.`,
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
		cl, err := adm.NewClient(n, gs)
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
	createCmd.AddCommand(createClientCmd)

	createClientCmd.Flags().StringP("name", "n", "", "Name of the client")
	createClientCmd.MarkFlagRequired("name")
	createClientCmd.Flags().StringSliceP("groups", "g", []string{}, "Groups to which the clients belong to.")
}
