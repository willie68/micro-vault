/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/willie68/micro-vault/cmd/cli/cmd/cmdutils"
)

// playbookCmd represents the playbook command
var playbookCmd = &cobra.Command{
	Use:   "playbook",
	Short: "Upload and execute a playbook",
	Long:  `This command will upload and execute a playbook.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		adm, err := cmdutils.AdminClient()
		if err != nil {
			return err
		}
		f, err := cmd.Flags().GetString("file")
		if err != nil {
			return err
		}
		if _, err := os.Stat(f); err != nil {
			return err
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		err = adm.SendPlaybook(string(b))
		if err != nil {
			return err
		}
		fmt.Println("playbook uploaded")
		return nil
	}}

func init() {
	rootCmd.AddCommand(playbookCmd)

	playbookCmd.Flags().StringP("file", "f", "", "playbook file")
	playbookCmd.MarkFlagRequired("file")
}
