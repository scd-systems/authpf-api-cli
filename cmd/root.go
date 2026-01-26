package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const API_VERSION = "1.1"

var (
	cfgFile string
	verbose bool
	version string
)

var rootCmd = &cobra.Command{
	Use:   "authpf-api-cli",
	Short: "authpf-api CLI tool for user and pf anchor management",
	Long: `authpf-api-cli is a command-line tool for managing authpf-api.
It can be used both on the server (for user and pf anchor management)
and on the client (for authentication and anchor loading).`,
	Version: version,
}

func Execute(ver string) error {
	version = ver
	rootCmd.Version = ver
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	default_config_filepath := fmt.Sprintf("config file (default is ~/%s/%s", CONFIG_DIR, CONFIG_FILE)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", default_config_filepath)
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	rootCmd.AddCommand(userCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(authCmd)
	rootCmd.AddCommand(authpfCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting home directory: %v\n", err)
			return
		}

		viper.AddConfigPath(home)
		viper.SetConfigName(".authpf-api-cli/config")
		viper.SetConfigType("yaml")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil && verbose {
		fmt.Fprintf(os.Stderr, "Using config file: %s\n", viper.ConfigFileUsed())
	}
}
