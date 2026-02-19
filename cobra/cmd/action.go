/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"project/cliIpc"
)

var action_list = map[string]string {
	"send_hello" : "mimic hello handshake",
	"getOntOper" : "mimic Onu2G,OnuG ME get",
	"setTOD"     : "mimic OLT-G TOD Set",
}
// actionCmd represents the action command
var actionCmd = &cobra.Command{
	Use:   "action",
	Short: "Perform the required action with vomci",
	Long: `List of actions available under voltmf`,
	Run: func(cmd *cobra.Command, args []string) {
		for _,y := range args {
			if y == "help" {
				for key,value := range action_list {
					fmt.Println(key, ":", value)
				}
			}else {
			    cliClient.RecvCmd(y)
		    }
		}
	},
}

func init() {
	rootCmd.AddCommand(actionCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// actionCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// actionCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
