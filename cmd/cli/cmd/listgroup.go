/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/willie68/micro-vault/cmd/cli/cmd/cmdutils"
)

// listgroupCmd represents the group command
var listgroupCmd = &cobra.Command{
	Use:   "group",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cl, ok := cmdutils.ReadCLConf()
		if !ok {
			return errors.New("you're not logged in, please use login command")
		}
		adm, err := cmdutils.AdminClient(*cl)
		if err != nil {
			return err
		}
		gs, err := adm.Groups()
		if err != nil {
			return err
		}
		fmt.Println("list of groups")
		fmt.Printf("%-32s, %-7s\r\n", "NAME", "CLIENT")
		for _, g := range gs {
			fmt.Printf("%-32s, %-7t\r\n", g.Name, g.IsClient)
		}
		return nil
	},
}

func init() {
	listCmd.AddCommand(listgroupCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// groupCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// groupCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
