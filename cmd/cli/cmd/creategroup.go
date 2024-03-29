/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/willie68/micro-vault/cmd/cli/cmd/cmdutils"
	"github.com/willie68/micro-vault/pkg/pmodel"
)

// createGroupCmd represents the groupt command
var createGroupCmd = &cobra.Command{
	Use:   "group",
	Short: "Create a new group",
	Long: `Create a new group in your mv instance. 
You can simply only add the name of the group, 
or you can optionally add some labels to it.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		adm, err := cmdutils.AdminClient()
		if err != nil {
			return err
		}
		n, err := cmd.Flags().GetString("name")
		if err != nil {
			return err
		}
		ls, err := cmd.Flags().GetStringSlice("labels")
		fmt.Println("Name: ", n)
		fmt.Println("Labels: ", cmdutils.Slice2String(ls))
		lm := cmdutils.Slice2Map(ls)
		g := pmodel.Group{
			Name:     n,
			Label:    lm,
			IsClient: false,
		}
		err = adm.AddGroup(g)
		if err != nil {
			return err
		}
		return nil
	},
}

func init() {
	createCmd.AddCommand(createGroupCmd)

	createGroupCmd.Flags().StringP("name", "n", "", "Name of the group")
	createGroupCmd.MarkFlagRequired("name")
	createGroupCmd.Flags().StringSliceP("labels", "l", []string{}, "Labels of the group, each label must be formatted as <lgn>:<Label> e.g. en:Group")
}
