package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const API_VERSION = "1.1"

const (
	VIPER_PARAM_USERNAME        = "api.username"
	VIPER_PARAM_PASSWORD        = "api.password"
	VIPER_PARAM_SERVER          = "api.server"
	VIPER_PARAM_CACERT          = "api.cacert"
	VIPER_PARAM_INSECURE        = "api.insecure"
	VIPER_PARAM_AUTHPF_TOKEN    = "api.token"
	VIPER_PARAM_AUTHPF_USERNAME = "api.authpf.username"
	VIPER_PARAM_AUTHPF_TIMEOUT  = "api.authpf.timeout"
)

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

	// Check for --version or -V flag before Cobra processes it
	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-V" {
			initConfig()
			if err := DisplayVersionInfo(ver); err != nil {
				return err
			}
			os.Exit(0)
		}
	}

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
	viper.SetEnvPrefix("AUTHPF")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil && verbose {
		fmt.Fprintf(os.Stderr, "Using config file: %s\n", viper.ConfigFileUsed())
	}
}
