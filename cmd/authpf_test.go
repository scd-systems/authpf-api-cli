package cmd

import (
	"testing"
	"time"
)

// TestFormatDuration verifies that formatDuration correctly formats time durations
func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		want     string
	}{
		// Negative durations (expired)
		{
			name:     "negative duration",
			duration: -1 * time.Hour,
			want:     "expired (server time difference)",
		},
		{
			name:     "zero duration",
			duration: 0,
			want:     "0m",
		},
		// Minutes only
		{
			name:     "1 minute",
			duration: 1 * time.Minute,
			want:     "1m",
		},
		{
			name:     "59 minutes",
			duration: 59 * time.Minute,
			want:     "59m",
		},
		// Hours and minutes
		{
			name:     "1 hour",
			duration: 1 * time.Hour,
			want:     "1h 0m",
		},
		{
			name:     "2 hours 15 minutes",
			duration: 2*time.Hour + 15*time.Minute,
			want:     "2h 15m",
		},
		{
			name:     "24 hours",
			duration: 24 * time.Hour,
			want:     "24h 0m",
		},
		{
			name:     "24 hours 59 minutes",
			duration: 24*time.Hour + 59*time.Minute,
			want:     "24h 59m",
		},
		// Large durations
		{
			name:     "100 hours",
			duration: 100 * time.Hour,
			want:     "100h 0m",
		},
		{
			name:     "1000 hours 30 minutes",
			duration: 1000*time.Hour + 30*time.Minute,
			want:     "1000h 30m",
		},
		// Edge cases with seconds (should be truncated)
		{
			name:     "1 hour 30 minutes 45 seconds",
			duration: 1*time.Hour + 30*time.Minute + 45*time.Second,
			want:     "1h 30m",
		},
		{
			name:     "59 seconds (less than 1 minute)",
			duration: 59 * time.Second,
			want:     "0m",
		},
		{
			name:     "1 minute 30 seconds",
			duration: 1*time.Minute + 30*time.Second,
			want:     "1m",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatDuration(tt.duration)
			if got != tt.want {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.duration, got, tt.want)
			}
		})
	}
}
