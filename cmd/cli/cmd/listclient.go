/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/willie68/micro-vault/cmd/cli/cmd/cmdutils"
	"github.com/willie68/micro-vault/pkg/client"
)

// listClientCmd represents the client command
var listClientCmd = &cobra.Command{
	Use:     "client",
	Short:   "list all clients",
	Long:    `listing of all registered clients of this mv instance`,
	Aliases: []string{"clients"},
	RunE: func(cmd *cobra.Command, args []string) error {
		adm, err := cmdutils.AdminClient()
		if err != nil {
			return err
		}
		g, err := cmd.Flags().GetString("group")
		if err != nil {
			return err
		}
		cs, err := adm.Clients(client.WithGroupFilter(g))
		if err != nil {
			return err
		}
		fmt.Printf("%-32s %-36s %s\r\n", "NAME", "ACCESSKEY", "GROUPS")
		for _, c := range cs {
			fmt.Printf("%-32s %-36s %s\r\n", c.Name, c.AccessKey, cmdutils.Slice2String(c.Groups))
		}
		return nil
	},
}

func init() {
	listCmd.AddCommand(listClientCmd)

	listClientCmd.Flags().StringP("group", "g", "", "list only clients belonging to that group")
}
