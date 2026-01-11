# authpf-cli

A command-line tool for managing the authpf-api server and client operations.

## Features

- **User Management**: Create, modify, and delete users with password hashing
- **Configuration Management**: Check and validate server configuration
- **Rule Management**: Activate, deactivate, and manage authpf rules
- **Status Monitoring**: Check server and client status, view active sessions and loaded rules
- **Authentication**: Login/logout and manage JWT tokens

## Installation

### Build from source

```bash
cd authapi-cli
go build -o authpf-cli
```

### Install globally

```bash
cd authapi-cli
go install
```

## Usage

### Server Mode (Local Operations)

#### User Management

```bash
# Create a new user
authpf-cli user create --username john --password mypassword --role user

# Modify a user
authpf-cli user modify --username john --password newpassword --role admin

# Delete a user
authpf-cli user delete --username john

# List all users
authpf-cli user list
```

#### Configuration

```bash
# Check configuration
authpf-cli config check

# Validate configuration
authpf-cli config validate

# Show configuration
authpf-cli config show
```

#### Rules Management

```bash
# List available rules
authpf-cli rules list

# List loaded rules
authpf-cli rules list --loaded

# Validate rules
authpf-cli rules validate

# Show rule content
authpf-cli rules show --rule user1

# Activate a rule (server mode)
authpf-cli rules activate --rule user1 --username john --user-ip 192.168.1.100
```

#### Status

```bash
# Check server status
authpf-cli status server

# List active sessions
authpf-cli status sessions

# List loaded rules
authpf-cli status rules
```

### Client Mode (Remote Operations)

#### Authentication

```bash
# Login to server
authpf-cli auth login --server https://api.example.com --username john --password mypassword

# Save token for future use
authpf-cli auth login --server https://api.example.com --username john --password mypassword --save

# Check authentication status
authpf-cli auth status

# Logout
authpf-cli auth logout
```

#### Remote Operations

```bash
# Activate a rule on remote server
authpf-cli rules activate --server https://api.example.com --token <jwt-token> --rule user1 --user-ip 192.168.1.100

# Deactivate a rule on remote server
authpf-cli rules deactivate --server https://api.example.com --token <jwt-token> --rule user1

# List rules from remote server
authpf-cli rules list --server https://api.example.com --token <jwt-token>

# Check remote server status
authpf-cli status server --server https://api.example.com

# Check client connection status
authpf-cli status client --server https://api.example.com --token <jwt-token>
```

## Configuration

The CLI can be configured via:

1. **Command-line flags** (highest priority)
2. **Environment variables**
3. **Config file** at `~/.authpf-cli/config.yaml`

### Config File Example

```yaml
auth:
  server: https://api.example.com
  username: john
  token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

server:
  config_path: /usr/local/etc/authpf-api.conf
  logfile: /var/log/authpf-api.log
```

## Global Flags

```
--config string    Config file (default is $HOME/.authpf-cli.yaml)
-v, --verbose      Verbose output
--help             Show help message
--version          Show version
```

## Examples

### Complete Server Setup Workflow

```bash
# 1. Create users
authpf-cli user create --username alice --password pass123 --role user
authpf-cli user create --username bob --password pass456 --role admin

# 2. Validate configuration
authpf-cli config validate

# 3. Check server status
authpf-cli status server

# 4. List loaded rules
authpf-cli status rules
```

### Complete Client Workflow

```bash
# 1. Login
authpf-cli auth login --server https://api.example.com --username alice --password pass123 --save

# 2. Check authentication
authpf-cli auth status

# 3. Activate your rules
authpf-cli rules activate --server https://api.example.com --rule user1 --user-ip 192.168.1.100

# 4. Check status
authpf-cli status client --server https://api.example.com

# 5. List your active rules
authpf-cli rules list --server https://api.example.com --loaded

# 6. Deactivate rules when done
authpf-cli rules deactivate --server https://api.example.com --rule user1

# 7. Logout
authpf-cli auth logout
```

## Development

### Project Structure

```
authapi-cli/
├── cmd/
│   ├── root.go       # Root command
│   ├── user.go       # User management commands
│   ├── config.go     # Configuration commands
│   ├── rules.go      # Rules management commands
│   ├── status.go     # Status commands
│   └── auth.go       # Authentication commands
├── main.go           # Entry point
├── go.mod            # Go module definition
└── README.md         # This file
```

### Building

```bash
# Build for current platform
go build -o authpf-cli

# Build for specific platform
GOOS=freebsd GOARCH=amd64 go build -o authpf-cli-freebsd

# Build with version info
go build -ldflags="-X main.Version=1.0.0" -o authpf-cli
```

## License

Same as authpf-api

## Contributing

Contributions are welcome! Please ensure:

1. Code follows Go conventions
2. All commands have help text
3. Error messages are clear and actionable
4. Both server and client modes are tested
