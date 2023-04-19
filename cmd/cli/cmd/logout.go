/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/willie68/micro-vault/cmd/cli/cmd/cmdutils"
)

// loginCmd represents the login command
var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "logout a microvault service",
	Long:  `With logout you invalidate a mvcli session.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := cmdutils.AdminLogout()
		if err != nil {
			return err
		}
		fmt.Println("client logged out")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}
