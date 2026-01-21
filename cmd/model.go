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
