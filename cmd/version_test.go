package cmd

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestParseVersion verifies that parseVersion correctly parses semantic versions.
func TestParseVersion(t *testing.T) {
	tests := []struct {
		input   string
		major   int
		minor   int
		wantErr bool
	}{
		{"2.1", 2, 1, false},
		{"0.0", 0, 0, false},
		{"10.20", 10, 20, false},
		{"invalid", 0, 0, true},
		{"1.2", 1, 2, false},
	}
	for _, tt := range tests {
		major, minor, err := parseVersion(tt.input)
		if (err != nil) != tt.wantErr {
			t.Fatalf("parseVersion(%s) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
		if !tt.wantErr && (major != tt.major || minor != tt.minor) {
			t.Fatalf("parseVersion(%s) = %d.%d, want %d.%d", tt.input, major, minor, tt.major, tt.minor)
		}
	}
}

// TestCompareVersions checks compatibility logic (major and minor must match).
func TestCompareVersions(t *testing.T) {
	tests := []struct {
		cli    string
		srv    string
		wantOK bool
	}{
		{"2.0", "2.0", true},
		{"2.1", "2.1", true},
		{"1.9", "2.0", false},
		{"2.0", "2.1", false},
	}
	for _, tt := range tests {
		err := compareAPIVersions(tt.cli, tt.srv)
		if (err == nil) != tt.wantOK {
			t.Fatalf("compareVersions(%s,%s) error = %v, wantOK %v", tt.cli, tt.srv, err, tt.wantOK)
		}
	}
}

// TestCheckAPIVersionCompatibility uses a mock server that returns API_Version in JSON.
func TestFullServerResponse(t *testing.T) {
	tests := []struct {
		name          string
		mockResponse  string
		cliAPIVersion string
		expectError   bool
	}{
		{
			name:          "compatible versions (same major.minor)",
			mockResponse:  `{"API": "1.0"}`,
			cliAPIVersion: "1.0",
			expectError:   false,
		},
		{
			name:          "incompatible major version",
			mockResponse:  `{"API": "2.0"}`,
			cliAPIVersion: "1.0",
			expectError:   true,
		},
		{
			name:          "incompatible minor version",
			mockResponse:  `{"API": "1.1"}`,
			cliAPIVersion: "1.0",
			expectError:   true,
		},
		{
			name:          "missing API_Version",
			mockResponse:  `{"version":"2.0.0"}`,
			cliAPIVersion: "1.0.0",
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(tt.mockResponse))
			})
			srv := httptest.NewServer(handler)
			defer srv.Close()

			API_VERSION = tt.cliAPIVersion
			err := checkAPIVersionCompatibility(srv.URL)
			if (err != nil) != tt.expectError {
				t.Fatalf("checkAPIVersionCompatibility() error = %v, expectError %v", err, tt.expectError)
			}
		})
	}
}
