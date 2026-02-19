/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var help_list = map[string]string{
	"help":"Displays available commands",
	"action":"sends msg to vomci function",
}

// helpCmd represents the help command
var helpCmd = &cobra.Command{
	Use:   "help",
	Short: "Display all the available commands",
	Long: `List of commands available `,
	Run: func(cmd *cobra.Command, args []string) {
		for y,x := range help_list {
			fmt.Println(y, ":", x)
		}
	},
}

func init() {
	rootCmd.AddCommand(helpCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// helpCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// helpCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
