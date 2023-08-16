/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// decodeCmd represents the update command
var decodeCmd = &cobra.Command{
	Use:   "decode",
	Short: "Decoding an object",
	Long:  `Decoding an object. e.g. certificate.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("decode called")
	},
}

func init() {
	rootCmd.AddCommand(decodeCmd)
}
