# authpf-api-cli

A command-line tool for managing the authpf-api server and client operations.

## Features

- **User Management**: Create, modify, and delete users with password hashing
- **Configuration Management**: Check and validate server configuration
- **Rule Management**: Activate, deactivate pf user rules
- **Status Monitoring**: Check server and client status, view active sessions and loaded rules
- **Authentication**: Login/logout and manage JWT tokens

## Installation

### Build from source

```bash
cd authpf-api-cli
make build
```

## Usage

### Server Mode (Local Operations)

#### User Management

```bash
# Create a new user
authpf-api-cli user create --username john --password mypassword --role user

# Modify a user
authpf-api-cli user modify --username john --password newpassword --role admin

# Delete a user
authpf-api-cli user delete --username john

# List all users
authpf-api-cli user list
```

#### Configuration

```bash
# Check configuration
authpf-api-cli config check

# Validate configuration
authpf-api-cli config validate

# Show configuration
authpf-api-cli config show
```

### Client Mode (Remote Operations)

#### Authentication

```bash
# Login to server
authpf-api-cli auth login --server https://api.example.com --username john --password mypassword

# Save token for future use
authpf-api-cli auth login --server https://api.example.com --username john --password mypassword --save

# Check authentication status
authpf-api-cli auth status

# Logout
authpf-api-cli auth logout
```

#### Authpf API Operations

```bash
# Activate a rule on remote server
authpf-api-cli authpf activate

# Activate a rule on remote server with specific timeout for 1h
authpf-api-cli authpf activate -t 1h

# Deactivate a rule on remote server
authpf-api-cli authpf deactivate

# Check client connection status
authpf-api-cli authpf status
```

## Configuration

The CLI can be configured via:

1. **Command-line flags** (highest priority)
2. **Environment variables**
3. **Config file** at `~/.authpf-api-cli/config.yaml`

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

### Complete Client Workflow

```bash
# 1. Login
authpf-api-cli auth login --server https://api.example.com --username alice --password pass123 --save

# 2. Check authentication
authpf-api-cli auth status

# 3. Activate your rules
authpf-api-cli authpf activate

# 4. Check status
authpf-api-cli authpf status

# 5. Deactivate rules when done
authpf-api-cli authpf deactivate

# 6. Logout
authpf-api-cli auth logout
```

## Development

### Building

```bash
# Build for current platform
make build

# Build for specific platform
make build GOOS=freebsd GOARCH=amd64

# Build with version info
go build -ldflags="-X main.Version=1.0.0" -o authpf-api-cli
```

## License

BSD 3-Clause License

See [License](LICENSE)

## Contributing

Contributions are welcome! Please ensure:

1. Code follows Go conventions
2. All commands have help text
3. Error messages are clear and actionable
4. Both server and client modes are tested
