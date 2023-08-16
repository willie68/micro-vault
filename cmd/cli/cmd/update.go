/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Updating parameters of an already created object",
	Long:  `Updating parameters of an already created object. e.g. client or group.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("update called")
	},
}

func init() {
	rootCmd.AddCommand(decodeCmd)
}
