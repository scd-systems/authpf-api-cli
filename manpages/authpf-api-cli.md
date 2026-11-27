# authpf-api-cli(1) - Command-line tool for authpf-api server and client operations

## NAME

**authpf-api-cli** — Command-line tool for managing authpf-api server and performing client operations

## SYNOPSIS

**authpf-api-cli** [*GLOBAL-OPTIONS*] *COMMANDS* [*OPTIONS*]

## DESCRIPTION

**authpf-api-cli** is a command-line tool for managing the **authpf-api** server and performing client operations. It can be used both on the server (for user and pf anchor management) and on the client (for authentication and anchor loading).

The tool provides functionality for:

- **Authentication**: Login/logout and manage JWT tokens for secure API access
- **Rule Management**: Activate and deactivate PF user anchors with configurable timeouts
- **Configuration**: Check and validate server configuration
- **User Management**: Create, modify, and delete users with secure password hashing
- **Status Monitoring**: Check server and client status, view active sessions and loaded anchors

## GLOBAL OPTIONS

**--config** _file_
:   Path to the configuration file. Defaults to `~/.authpf-api-cli/config` if not set.

**--verbose**, **-v**
:   Enable verbose output for debugging purposes.

**--help**, **-h**
:   Display help information and exit.

**--version**
:   Display version information and exit. The configured server is asked for its version as well and gets one second to answer: a server that is slow or unreachable costs a `server_note` in the output instead of a wait, and the command still exits 0.

## COMMANDS

### auth
Authentication and session management

  **auth login**
  Authenticate with the authpf-api server and obtain a JWT token. On success the token validity and its remaining lifetime are displayed.

**Options:**

**--server** *URL*
: URL of the authpf-api server (e.g., https://api.example.com). Required for first login.

**--username** *USERNAME*
: Username for authentication. Required for first login.

**--password**, **-p**
: Ask for the password at the terminal, hidden. A password is never given as a value on the command line: a value there sits in the process argument vector, which every user logged in on that host can read while the process runs, and it stays in the shell history and in the CI job log too. Without **-p** the credential comes from **AUTHPF_API_PASSWORD**, then from the config file, then from the credentials file of the last login.

**--cacert** *FILE*, **-c** *FILE*
: Path to a custom CA certificate file for HTTPS connections with self-signed certificates.

**--insecure**
: Skip TLS certificate verification (not recommended for production).

#### auth logout
Logout from the authpf-api server and remove the stored JWT token.

#### auth status
Display the current authentication status and token information.

The server decides whether the token is valid. Token expiry is reported on the server clock, so a client clock that runs ahead or behind never turns a valid token into an expired one. If the two clocks differ by more than two minutes, the CLI prints a time difference warning and names both times.

The command exits with 0 only when the server accepts the token. A missing token, a rejected token and an unreachable server all exit with 1, so `auth status` can be used as a condition in scripts.

### authpf
PF anchor management

#### authpf activate
Activate pf rules for the authenticated user.

If the config file holds no token but a credentials file with username and password exists, activate logs in first and stores the new token. The server URL must still be configured, a credentials file does not contain it.

**Options:**

**--timeout** *TIME*, **-t** *TIME*
: Override the default timeout for rule activation (e.g., 30m, 1h, 2h). Default is configured on the server.

**--username** *USERNAME*, **-u** *USERNAME*
: Activate rules for another user (requires appropriate permissions).

#### authpf deactivate
Deactivate pf rules for the authenticated user.

**Options:**

**username** *USERNAME*, **-u** *USERNAME*
: Deactivate rules for another user (requires appropriate permissions).

**all** 
: Deactivate all activated rules (admin only).

#### authpf status
Display the status of activated pf rules.

The remaining anchor lifetime is calculated on the server clock. A time difference warning is printed whenever client and server clocks differ by more than two minutes.

**Options:**

**all** 
: Display status of all activated rules (admin only).


### user
User management (server-side)

Every command below that changes the server configuration checks the result against the rules the authpf-api server enforces on its `rbac.users` section, and refuses to write when the server would refuse to start from the file: a user name outside `[a-zA-Z0-9_-]` or longer than 255 characters, a role the configuration does not define, a `userId` that is negative or that another user already uses, or the removal of the last remaining user. A refused change leaves the file untouched.

#### user create
Create a new user on the authpf-api server.

**Options:**

**username** *USERNAME*
: Username for the new user. Required.

**password** *PASSWORD*
: Password for the new user. Required. If not provided, will prompt interactively.

**role** *ROLE*
: User role: `user` or `admin`. Default is `user`.

#### user modify
Modify an existing user on the authpf-api server.

**Options:**

**username** *USERNAME*
: Username of the user to modify. Required.

**password** *PASSWORD*
: New password for the user. If not provided, password remains unchanged.

**role** *ROLE*
: New role for the user: `user` or `admin`.

#### user delete
Delete a user from the authpf-api server.

**Options:**

**username** *USERNAME*
: Username of the user to delete. Required.

#### user list
List all users on the authpf-api server.

### config
Configuration management

#### config show
Display the current server configuration.

## ENVIRONMENT

**AUTHPF_API_SERVER**
: URL of the authpf-api server. Overrides the configured server value.

**AUTHPF_API_USERNAME**
: Username for authentication. Overrides the configured username.

**AUTHPF_API_PASSWORD**
: The credential sent for authentication, overriding the configured and the stored one. The server compares what arrives against the stored hash, so for the usual `bcrypt` hash in the server config (the `$2a$…` form) this has to be the **SHA-256 hex digest of the password**, not the password itself: `printf %s "$pw" | sha256sum`. The same rule applies to `api.password` in the config file and to `credentials.yaml`; **-p** on **auth login** is the path that takes the password as typed and hashes it itself. An environment variable is readable by its owning user and root only, which a command line value is not, but an inline `AUTHPF_API_PASSWORD=… authpf-api-cli` still lands in the shell history and shows up in `docker inspect`.

**AUTHPF_API_TOKEN**
: JWT token for authentication. Overrides the stored token.

**AUTHPF_API_CACERT**
: Path to a custom CA certificate file.

**AUTHPF_API_INSECURE**
: Skip TLS certificate verification if set to `true`.

**AUTHPF_API_AUTHPF_USERNAME**
: Default authpf username for operations.

**AUTHPF_API_AUTHPF_TIMEOUT**
: Default timeout for authpf rule activation.

## CONFIGURATION

**authpf-api-cli** is configured via a YAML configuration file, typically located at `~/.authpf-api-cli/config`. The configuration file stores:

- API server URL
- JWT token (automatically stored after login)
- CA certificate path for HTTPS connections

**Example configuration file:**

```yaml
api:
  server: https://api.example.com
  token: ""
  cacert: ""
  insecure: false
```

## EXAMPLES

**Login to API and get Token**
: authpf-api-cli auth login --server https://api.example.com --username john -p
: authpf-api-cli auth login --server https://api.example.com --username john -p -c ca-root.crt

**Logout from API**
: authpf-api-cli auth logout

**Show Auth Status**
: authpf-api-cli auth status

**Activate AuthPF Anchor**
: authpf-api-cli authpf activate
: authpf-api-cli authpf activate -t 1h
: authpf-api-cli authpf activate -u user2

**Deactivate Anchor**
: authpf-api-cli authpf deactivate
: authpf-api-cli authpf deactivate -u user2
: authpf-api-cli authpf deactivate --all

**Show Anchor Status (activated)**
: authpf-api-cli authpf status
: authpf-api-cli authpf status --all

**Create API User**
: authpf-api-cli user create --username john --password mypassword --role user
: authpf-api-cli user create --username admin1 --password adminpass --role admin

**Modify API User**
: authpf-api-cli user modify --username john --password newpassword
: authpf-api-cli user modify --username john --role admin

**Remove API User**
: authpf-api-cli user delete --username john

**List API Users**
: authpf-api-cli user list

**Show current API Config**
: authpf-api-cli config show

### Typical AuthPF User Workflow

```bash
# Step 1: Login to the server (only required for first time)
authpf-api-cli auth login --server https://api.example.com --username alice -p

# To get a new token (if already configured server and username/password)
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

### Server Administrator Workflow

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

# Display configuration
authpf-api-cli config show
```

### Advanced Usage

```bash
# Login with custom CA certificate
authpf-api-cli auth login --server https://api.example.com --username john -p -c /path/to/ca.crt

# Activate anchor for 2 hours
authpf-api-cli authpf activate -t 2h

# Activate another user's anchor (admin only)
authpf-api-cli authpf activate -u user2

# Check all active connections (admin only)
authpf-api-cli authpf status --all

# Deactivate all anchors (admin only)
authpf-api-cli authpf deactivate --all

# Verbose output for debugging
authpf-api-cli --verbose auth login --server https://api.example.com --username john -p
```

## FILES

```
~/.authpf-api-cli/config — Default configuration file
~/.authpf-api-cli/credentials — Credentials File (Username, Hashed Password)
```

## SEE ALSO

authpf-api.conf(5)

## HISTORY

**authpf-api-cli** was created as a command-line interface to the **authpf-api** server, providing both client-side operations (authentication, rule activation/deactivation) and server-side administration (user management, configuration).

## AUTHORS

bofh@scd-systems.net
