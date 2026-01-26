package cmd

type ConfigFile struct {
	Defaults ConfigFileDefaults `yaml:"defaults"`
	Server   ConfigFileServer   `yaml:"server"`
	AuthPF   ConfigFileAuthPF   `yaml:"authpf"`
	Rbac     ConfigFileRbac     `yaml:"rbac"`
}

type ConfigFileDefaults struct {
	PfctlBinary string `yaml:"pfctlBinary"`
}

type ConfigFileAuthPF struct {
	Timeout             string   `yaml:"timeout"`
	UserRulesRootFolder string   `yaml:"userRulesRootFolder"`
	UserRulesFile       string   `yaml:"userRulesFile"`
	AnchorName          string   `yaml:"anchorName"`
	FlushFilter         []string `yaml:"flushFilter"`
}

type ConfigFileServer struct {
	Bind            string              `yaml:"bind"`
	Port            uint16              `yaml:"port"`
	SSL             ConfigFileServerSSL `yaml:"ssl"`
	ElevatorMode    string              `yaml:"elevatorMode"`
	Logfile         string              `yaml:"logfile"`
	JwtTokenTimeout string              `yaml:"jwtTokenTimeout"`
	JwtSecret       string              `yaml:"jwtSecret"`
}

type ConfigFileServerSSL struct {
	Certificate string `yaml:"certificate"`
	Key         string `yaml:"key"`
}

type ConfigFileRbac struct {
	Roles map[string]ConfigFileRbacRoles `yaml:"roles"`
	Users map[string]ConfigFileRbacUsers `yaml:"users"`
}

type ConfigFileRbacRoles struct {
	Permissions []string `yaml:"permissions"`
}

type ConfigFileRbacUsers struct {
	UserRulesFile string `yaml:"userRulesFile,omitempty"`
	Password      string `yaml:"password"`
	Role          string `yaml:"role"`
	UserID        int    `yaml:"userId,omitempty"`
}

// Global Variables
const (
	CONFIG_DIR                        = ".authpf-api-cli"
	CONFIG_FILE                       = "config.yaml"
	CREDENTIALS_FILE                  = "credentials.yaml"
	ENDPOINT_INFO                     = "/info"
	METHOD_ENDPOINT_INFO              = "GET"
	ENDPOINT_LOGIN                    = "/login"
	METHOD_ENDPOINT_LOGIN             = "POST"
	ENDPOINT_AUTHPF_ACTIVATE          = "/api/v1/authpf/activate"
	ENDPOINT_AUTHPF_ALL               = "/api/v1/authpf/all"
	METHOD_ENDPOINT_AUTHPF_ACTIVATE   = "POST"
	METHOD_ENDPOINT_AUTHPF_VIEW       = "GET"
	ENDPOINT_AUTHPF_DEACTIVATE        = "/api/v1/authpf/activate"
	METHOD_ENDPOINT_AUTHPF_DEACTIVATE = "DELETE"
)
