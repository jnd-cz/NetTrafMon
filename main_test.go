package main

import (
	"testing"
	"time"
)

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{
			name:     "less than 1 second",
			duration: 500 * time.Millisecond,
			expected: "1 second", // Expected: 0 seconds as per previous logic, but 500ms rounds to 1s
		},
		{
			name:     "less than 0.5 second",
			duration: 400 * time.Millisecond,
			expected: "0 seconds",
		},
		{
			name:     "only seconds",
			duration: 30 * time.Second,
			expected: "30 seconds",
		},
		{
			name:     "seconds rounding up",
			duration: 30*time.Second + 600*time.Millisecond,
			expected: "31 seconds",
		},
		{
			name:     "seconds rounding down",
			duration: 30*time.Second + 400*time.Millisecond,
			expected: "30 seconds",
		},
		{
			name:     "minutes and seconds",
			duration: 2*time.Minute + 30*time.Second,
			expected: "2 minutes 30 seconds",
		},
		{
			name:     "hours minutes and seconds",
			duration: 1*time.Hour + 2*time.Minute + 30*time.Second,
			expected: "1 hours 2 minutes 30 seconds", // Note: "1 hours" is slightly unnatural, "1 hour" would be better.
		},
		{
			name:     "days hours minutes and seconds",
			duration: 2*24*time.Hour + 3*time.Hour + 4*time.Minute + 5*time.Second,
			expected: "2 days 3 hours 4 minutes 5 seconds",
		},
		{
			name:     "hours and seconds (zero minutes)",
			duration: 1*time.Hour + 5*time.Second,
			expected: "1 hours 5 seconds", // Note: "1 hours"
		},
		{
			name:     "days and minutes (zero hours and seconds)",
			duration: 1*24*time.Hour + 5*time.Minute,
			expected: "1 days 5 minutes", // Note: "1 days"
		},
		{
			name:     "exactly zero",
			duration: 0 * time.Second,
			expected: "0 seconds",
		},
		{
			name:     "1 day",
			duration: 1 * 24 * time.Hour,
			expected: "1 days", // Note: "1 days"
		},
		{
			name:     "1 hour",
			duration: 1 * time.Hour,
			expected: "1 hours", // Note: "1 hours"
		},
		{
			name:     "1 minute",
			duration: 1 * time.Minute,
			expected: "1 minutes", // Note: "1 minutes"
		},
		{
			name:     "59 seconds",
			duration: 59 * time.Second,
			expected: "59 seconds",
		},
		{
			name:     "59 minutes 59 seconds",
			duration: 59*time.Minute + 59*time.Second,
			expected: "59 minutes 59 seconds",
		},
		{
			name:     "23 hours 59 minutes 59 seconds",
			duration: 23*time.Hour + 59*time.Minute + 59*time.Second,
			expected: "23 hours 59 minutes 59 seconds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := formatUptime(tt.duration)
			if actual != tt.expected {
				t.Errorf("formatUptime(%v) = %q, want %q", tt.duration, actual, tt.expected)
			}
		})
	}
}
