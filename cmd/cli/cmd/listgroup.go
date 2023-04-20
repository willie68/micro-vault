/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/willie68/micro-vault/cmd/cli/cmd/cmdutils"
)

// listgroupCmd represents the group command
var listgroupCmd = &cobra.Command{
	Use:     "group",
	Short:   "list all registered groups",
	Long:    `list all registered groups of this mv instance`,
	Aliases: []string{"groups"},
	RunE: func(cmd *cobra.Command, args []string) error {
		adm, err := cmdutils.AdminClient()
		if err != nil {
			return err
		}
		gs, err := adm.Groups()
		if err != nil {
			return err
		}
		fmt.Printf("%-32s %-7s %s\r\n", "NAME", "CLIENT", "LABELS")
		for _, g := range gs {
			s := ""
			for k, v := range g.Label {
				if s != "" {
					s = s + ", "
				}
				s = fmt.Sprintf("%s%s:%s", s, k, v)
			}
			fmt.Printf("%-32s %-7t %s\r\n", g.Name, g.IsClient, s)
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
