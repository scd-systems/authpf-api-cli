# authpf-api-cli

A command-line tool for managing the authpf-api server and performing client operations.

## 🎯 What Can This Tool Do?

- **🔑 Authentication**: Login/logout and manage JWT tokens
- **🔐 Rule Management**: Activate and deactivate PF user anchors
- **⚙️ Configuration**: Check and validate server configuration
- **👥 User Management**: Create, modify, and delete users with secure password hashing
- **📊 Status Monitoring**: Check server and client status, view active sessions and loaded anchors

## 📦 Installation

### Use Binary

Download latest release from https://github.com/scd-systems/authpf-api-cli/releases for your OS.

### Build from Source

```bash
cd authpf-api-cli
make build
```

This creates the executable `authpf-api-cli` under `./build` folder.

## 🚀 Quick Start

### For Client Users

Work with a remote server:

```bash
# 1. Login to the server
authpf-api-cli auth login --server https://api.example.com --username john --password mypassword

# Login with a custom CA certificate
authpf-api-cli auth login --server https://api.example.com --username john --password mypassword -c ca-root.crt

# 2. Check login status
authpf-api-cli auth status

# 3. Activate your anchor (for 1 hour)
authpf-api-cli authpf activate -t 1h

# Activate another user's anchor
authpf-api-cli authpf activate -u user2

# 4. Check status
authpf-api-cli authpf status

# Check all connections
authpf-api-cli authpf status --all

# 5. Deactivate anchors
authpf-api-cli authpf deactivate

# Deactivate all anchors
authpf-api-cli authpf deactivate --all

# 6. Logout
authpf-api-cli auth logout
```

### For Server Administrators

Manage users on the local server:

```bash
# Create a new user
authpf-api-cli user create --username john --password mypassword --role user

# Change a user's password
authpf-api-cli user modify --username john --password newpassword

# Promote user to admin
authpf-api-cli user modify --username john --role admin

# List all users
authpf-api-cli user list

# Delete a user
authpf-api-cli user delete --username john
```

Check server configuration:

```bash
# Display configuration
authpf-api-cli config show
```

## 📋 Typical AuthPF User Workflow

```bash
# Step 1: Login to the server (only required for first time)
authpf-api-cli auth login --server https://api.example.com --username alice --password pass123

# To get a new token (if already configured server and username/password -> step 1)
authpf-api-cli auth login 

# Step 2: Check login status
authpf-api-cli auth status

# Step 3: Activate your anchors
authpf-api-cli authpf activate

# Step 4: Check anchor status
authpf-api-cli authpf status

# Step 5: When done - deactivate anchors
authpf-api-cli authpf deactivate

# Step 6: Logout
authpf-api-cli auth logout
```

## 🔨 Development

### Build for Different Platforms

```bash
# Build for current platform
make build

# Build for FreeBSD (64-bit)
make build GOOS=freebsd GOARCH=amd64
```

## 🤝 Contributing

Contributions are welcome! Please follow the requirements above.

### Requirements for Contributing

If you'd like to contribute to this project:

1. Code follows Go conventions
2. All commands have help text
3. Error messages are clear and actionable
4. Both server and client modes are tested

## 📄 License

BSD 3-Clause License

See [LICENSE](LICENSE)

