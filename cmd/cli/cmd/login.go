/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/spf13/cobra"
	"github.com/willie68/micro-vault/cmd/cli/cmd/cmdutils"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login into a microvault service",
	Long: `With login you start an mvcli session. 
Please enter the URL for the service, 
as well as the root user name and password.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		url, err := cmd.Flags().GetString("url")
		if err != nil {
			return err
		}
		u, err := cmd.Flags().GetString("username")
		if err != nil {
			return err
		}
		p, err := cmd.Flags().GetString("password")
		if err != nil {
			return err
		}
		a, err := cmd.Flags().GetString("accesskey")
		if err != nil {
			return err
		}
		s, err := cmd.Flags().GetString("secret")
		if err != nil {
			return err
		}
		if u != "" && p != "" {
			_, err = cmdutils.AdminLogin(u, p, url)
			if err != nil {
				return err
			}
		} else {
			_, err = cmdutils.ClientLogin(a, s, url)
			if err != nil {
				return err
			}
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)

	loginCmd.Flags().String("url", "https://localhost:8443", "insert the url to the mv service")
	loginCmd.MarkFlagRequired("url")
	loginCmd.Flags().StringP("username", "u", "root", "insert the admin account name")
	loginCmd.Flags().StringP("password", "p", "", "insert the password of the admin account")
	loginCmd.MarkFlagsRequiredTogether("username", "password")

	loginCmd.Flags().StringP("accesskey", "a", "", "insert the client acceskey")
	loginCmd.Flags().StringP("secret", "s", "", "insert the secret of the client")
	loginCmd.MarkFlagsRequiredTogether("accesskey", "secret")
}
