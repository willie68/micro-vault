/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// createCmd represents the create command, creating an object in the microvault system
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an object in your micro-vault instance",
	Long:  `Creating object new in your micro-vault instance, client, group.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("create called")
	},
}

func init() {
	rootCmd.AddCommand(createCmd)
}
