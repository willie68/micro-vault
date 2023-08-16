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

// updateGroupCmd represents the group command
var updateGroupCmd = &cobra.Command{
	Use:   "group",
	Short: "Update a group with new labels",
	Long:  `Update a group with new labels`,
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
		if err != nil {
			return err
		}
		lm := cmdutils.Slice2Map(ls)
		g := pmodel.Group{
			Name:  n,
			Label: lm,
		}
		err = adm.UpdateGroup(g)
		if err != nil {
			return err
		}

		gl, err := adm.Group(n)
		if err != nil {
			return err
		}
		fmt.Printf("Name      : %s\r\n", gl.Name)
		fmt.Printf("is Client : %t\r\n", gl.IsClient)
		fmt.Printf("Label      : %s\r\n", cmdutils.Labels2String(gl.Label))
		return nil
	},
}

func init() {
	decodeCmd.AddCommand(updateGroupCmd)

	updateGroupCmd.Flags().StringP("name", "n", "", "Name of the group")
	updateGroupCmd.MarkFlagRequired("name")
	updateGroupCmd.Flags().StringSliceP("labels", "l", []string{}, "Labels of the group, each label must be formatted as <lgn>:<Label> e.g. en:Group")
	updateGroupCmd.MarkFlagRequired("labels")
}
