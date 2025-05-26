package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3" // Import for side-effect
)

// originalDB holds the original global db instance.
var originalDB *sql.DB

// testNow is a fixed point in time for consistent tests.
// Let's set it to July 15, 2023, 10:00:00 UTC for predictability.
var testNow = time.Date(2023, time.July, 15, 10, 0, 0, 0, time.UTC)

// timeNow is a variable that stores the function to get the current time.
// This allows us to override it in tests.
// var timeNowFunc = time.Now // Removed, will use main.timeNowFunc

func setupTestDB(t *testing.T) *AppContext {
	t.Helper()

	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0666)
	if err != nil {
		t.Fatalf("Failed to open %s: %v", os.DevNull, err)
	}
	// Create a logger for the test AppContext, writing to os.DevNull
	testAppContextLogger := log.New(devNull, "TEST_APP_CTX_NETMONITOR: ", log.Ldate|log.Ltime|log.Lshortfile)

	testDb, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open in-memory database: %v", err)
	}

	// Store the original global db and logger if they exist and restore them in Cleanup.
	// This is relevant if other tests in the same package might rely on the global vars.
	// For this specific refactoring, the globals are being phased out, but it's good practice in mixed environments.
	// originalGlobalLogger := logger // logger is no longer a global in main package that tests would use directly.
	// originalGlobalDB := db 

	appCtx := &AppContext{
		DB:               testDb,
		Logger:           testAppContextLogger, // Use the logger created for this context
		Interfaces:       []string{"eth0", "eth1", "eth2"}, 
		LastBytes:        make(map[string]map[string]uint64),
		EffectiveDBPath:  ":memory:", 
		EffectiveLogPath: os.DevNull, 
		StartTime:        testNow,    
		AppVersion:       "test-version",
	}

	// Initialize LastBytes for test interfaces as detectInterfaces would in main
	for _, ifaceName := range appCtx.Interfaces {
		if appCtx.LastBytes[ifaceName] == nil {
			appCtx.LastBytes[ifaceName] = make(map[string]uint64)
		}
		appCtx.LastBytes[ifaceName]["rx"] = 0
		appCtx.LastBytes[ifaceName]["tx"] = 0
	}


	_, err = appCtx.DB.Exec(`CREATE TABLE IF NOT EXISTS network_traffic (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME,
		interface TEXT,
		bytes_received INTEGER,
		bytes_sent INTEGER,
		bytes_combined INTEGER
	)`)
	if err != nil {
		appCtx.DB.Close()
		t.Fatalf("Failed to create table: %v", err)
	}

	_, err = appCtx.DB.Exec(`CREATE INDEX IF NOT EXISTS idx_network_traffic_timestamp ON network_traffic(timestamp)`)
	if err != nil {
		appCtx.DB.Close()
		t.Fatalf("Failed to create index idx_network_traffic_timestamp: %v", err)
	}
	_, err = appCtx.DB.Exec(`CREATE INDEX IF NOT EXISTS idx_network_traffic_interface ON network_traffic(interface)`)
	if err != nil {
		appCtx.DB.Close()
		t.Fatalf("Failed to create index idx_network_traffic_interface: %v", err)
	}

	t.Cleanup(func() {
		appCtx.DB.Close()
		// No need to restore global logger as it's not set by setupTestDB directly on the main package's global.
		// If there was a global logger in the main package that tests might interact with *outside* of AppContext,
		// then restoration would be needed. But here, appCtx.Logger is self-contained for the test context.
	})

	return appCtx
}

func addTrafficRecord(t *testing.T, appCtx *AppContext, ts time.Time, iface string, rx, tx, combined uint64) {
	t.Helper()
	_, err := appCtx.DB.Exec(
		"INSERT INTO network_traffic (timestamp, interface, bytes_received, bytes_sent, bytes_combined) VALUES (?, ?, ?, ?, ?)",
		ts.Format("2006-01-02 15:04:05"),
		iface,
		rx,
		tx,
		combined,
	)
	if err != nil {
		t.Fatalf("Failed to insert traffic data: %v", err)
	}
}

// mockTimeNow sets the application's current time to testNow.
func mockTimeNow() time.Time {
	return testNow
}

func TestGetTrafficStats_PreviousMonth(t *testing.T) {
	appCtx := setupTestDB(t)
	
	originalTimeNow := timeNowFunc // Save current time function from main package
	timeNowFunc = mockTimeNow      // Override with mock
	t.Cleanup(func() { timeNowFunc = originalTimeNow }) // Restore original time function

	// Data for previous month (June 2023)
	// testNow is July 15, 2023. Previous month is June 2023.
	prevMonthStart := time.Date(testNow.Year(), testNow.Month()-1, 1, 0, 0, 0, 0, testNow.Location()) // June 1st
	addTrafficRecord(t, appCtx, prevMonthStart.Add(12*time.Hour), "eth0", 100, 200, 300)
	addTrafficRecord(t, appCtx, prevMonthStart.Add(36*time.Hour), "eth0", 150, 250, 400)
	// Total for June: 700B

	addTrafficRecord(t, appCtx, testNow.Add(-2*time.Hour), "eth0", 50, 50, 100) // Current month data

	stats, err := getTrafficStats(appCtx, "eth0", "previous_month")
	if err != nil {
		t.Fatalf("getTrafficStats failed for previous_month: %v", err)
	}

	if stats.BytesCombined != 700 {
		t.Errorf("PreviousMonth BytesCombined: got %d, want %d", stats.BytesCombined, 700)
	}
	// New Rule: ExtrapolatedMonthlyCombinedRate == BytesCombined for "previous_month"
	if stats.ExtrapolatedMonthlyCombinedRate != stats.BytesCombined {
		t.Errorf("PreviousMonth ExtrapolatedMonthlyCombinedRate: got %d, want %d (same as BytesCombined)", stats.ExtrapolatedMonthlyCombinedRate, stats.BytesCombined)
	}
	expectedTimeRange := fmt.Sprintf("Previous Month (%s)", prevMonthStart.Format("January 2006"))
	if stats.TimeRange != expectedTimeRange {
		t.Errorf("PreviousMonth TimeRange: got %q, want %q", stats.TimeRange, expectedTimeRange)
	}
	if stats.HumanExtrapolatedMonthlyCombinedRate != humanReadableSize(stats.BytesCombined) {
		t.Errorf("PreviousMonth HumanExtrapolatedMonthlyCombinedRate: got %q, want %q", stats.HumanExtrapolatedMonthlyCombinedRate, humanReadableSize(stats.BytesCombined))
	}
}

func TestGetTrafficStats_Last30Days(t *testing.T) { // Renamed from TestGetTrafficStats_CurrentMonth
	appCtx := setupTestDB(t)
	
	originalTimeNow := timeNowFunc // Save current time function from main package
	timeNowFunc = mockTimeNow      // Override with mock
	t.Cleanup(func() { timeNowFunc = originalTimeNow }) // Restore original time function

	// Data for "Last 30 Days"
	// testNow is July 15, 2023. So, "Last 30 Days" starts around June 15, 2023.
	var totalBytesLast30Days uint64 = 0
	// Data within last 30 days
	addTrafficRecord(t, appCtx, testNow.Add(-1*24*time.Hour), "eth0", 1000, 200, 1200) // July 14th
	totalBytesLast30Days += 1200
	addTrafficRecord(t, appCtx, testNow.Add(-15*24*time.Hour), "eth0", 500, 50, 550)   // June 30th
	totalBytesLast30Days += 550
	
	// Data outside last 30 days (should be ignored)
	addTrafficRecord(t, appCtx, testNow.Add(-35*24*time.Hour), "eth0", 10, 10, 20) // Approx June 10th

	stats, err := getTrafficStats(appCtx, "eth0", "month") // "month" key now means "Last 30 Days"
	if err != nil {
		t.Fatalf("getTrafficStats failed for month (Last 30 Days): %v", err)
	}

	if stats.BytesCombined != totalBytesLast30Days {
		t.Errorf("Last30Days BytesCombined: got %d, want %d", stats.BytesCombined, totalBytesLast30Days)
	}
	if stats.TimeRange != "Last 30 Days" {
		t.Errorf("Last30Days TimeRange: got %q, want %q", stats.TimeRange, "Last 30 Days")
	}
	// New Rule: ExtrapolatedMonthlyCombinedRate == BytesCombined for "month" (Last 30 Days)
	if stats.ExtrapolatedMonthlyCombinedRate != stats.BytesCombined {
		t.Errorf("Last30Days ExtrapolatedMonthlyCombinedRate: got %d, want %d (same as BytesCombined)", stats.ExtrapolatedMonthlyCombinedRate, stats.BytesCombined)
	}
	if stats.HumanExtrapolatedMonthlyCombinedRate != humanReadableSize(stats.BytesCombined) {
		t.Errorf("Last30Days HumanExtrapolatedMonthlyCombinedRate: got %q, want %q", stats.HumanExtrapolatedMonthlyCombinedRate, humanReadableSize(stats.BytesCombined))
	}
}

func TestGetTrafficStats_OtherTimeRanges(t *testing.T) {
	appCtx := setupTestDB(t)
	
	originalTimeNow := timeNowFunc // Save current time function from main package
	timeNowFunc = mockTimeNow      // Override with mock
	t.Cleanup(func() { timeNowFunc = originalTimeNow }) // Restore original time function

	const iface = "eth1"
	daysInCurrentActualMonth := float64(time.Date(testNow.Year(), testNow.Month()+1, 0, 0, 0, 0, 0, testNow.Location()).Day()) // July has 31 days

	// --- HOUR ---
	addTrafficRecord(t, appCtx, testNow.Add(-30*time.Minute), iface, 100, 100, 200) // 200B
	addTrafficRecord(t, appCtx, testNow.Add(-90*time.Minute), iface, 50, 50, 100)  // Outside last hour
	
	statsHour, err := getTrafficStats(appCtx, iface, "hour")
	if err != nil {t.Fatalf("getTrafficStats failed for hour: %v", err)}
	if statsHour.BytesCombined != 200 {t.Errorf("Hour BytesCombined: got %d, want %d", statsHour.BytesCombined, 200)}
	
	durationHour := 1.0 / 24.0
	expectedHourExtra := uint64((float64(statsHour.BytesCombined) / durationHour) * daysInCurrentActualMonth)
	if statsHour.ExtrapolatedMonthlyCombinedRate != expectedHourExtra {
		t.Errorf("Hour Extrapolated: got %d, want %d (based on %f days in month)", statsHour.ExtrapolatedMonthlyCombinedRate, expectedHourExtra, daysInCurrentActualMonth)
	}

	// --- DAY ---
	// Record from -90*time.Minute (100B) is also within the last day.
	addTrafficRecord(t, appCtx, testNow.Add(-12*time.Hour), iface, 300, 300, 600) // 600B (within last 24h)
	// Total for day: 200B (from -30min) + 100B (from -90min) + 600B (from -12hr) = 900B
	statsDay, err := getTrafficStats(appCtx, iface, "day")
	if err != nil {t.Fatalf("getTrafficStats failed for day: %v", err)}
	if statsDay.BytesCombined != 900 {t.Errorf("Day BytesCombined: got %d, want %d", statsDay.BytesCombined, 900)}

	durationDay := 1.0
	expectedDayExtra := uint64((float64(statsDay.BytesCombined) / durationDay) * daysInCurrentActualMonth)
	if statsDay.ExtrapolatedMonthlyCombinedRate != expectedDayExtra {
		t.Errorf("Day Extrapolated: got %d, want %d (based on %f days in month)", statsDay.ExtrapolatedMonthlyCombinedRate, expectedDayExtra, daysInCurrentActualMonth)
	}

	// --- WEEK ---
	// All records from "DAY" are within the last week.
	addTrafficRecord(t, appCtx, testNow.Add(-3*24*time.Hour), iface, 1000, 1000, 2000) // 2000B (within last 7d)
	// Total for week: 900B (from day) + 2000B (from -3days) = 2900B
	statsWeek, err := getTrafficStats(appCtx, iface, "week")
	if err != nil {t.Fatalf("getTrafficStats failed for week: %v", err)}
	if statsWeek.BytesCombined != 2900 {t.Errorf("Week BytesCombined: got %d, want %d", statsWeek.BytesCombined, 2900)}

	durationWeek := 7.0
	expectedWeekExtra := uint64((float64(statsWeek.BytesCombined) / durationWeek) * daysInCurrentActualMonth)
	if statsWeek.ExtrapolatedMonthlyCombinedRate != expectedWeekExtra {
		t.Errorf("Week Extrapolated: got %d, want %d (based on %f days in month)", statsWeek.ExtrapolatedMonthlyCombinedRate, expectedWeekExtra, daysInCurrentActualMonth)
	}
	
	// --- YEAR ---
	// All records from "WEEK" are within the last year.
	addTrafficRecord(t, appCtx, testNow.AddDate(0, -6, 0), iface, 5000, 5000, 10000) // 10000B (within last year)
	// Total for year: 2900B (from week) + 10000B (from -6months) = 12900B
	statsYear, err := getTrafficStats(appCtx, iface, "year")
	if err != nil {t.Fatalf("getTrafficStats failed for year: %v", err)}
	if statsYear.BytesCombined != 12900 {t.Errorf("Year BytesCombined: got %d, want %d", statsYear.BytesCombined, 12900)}

	expectedYearExtra := uint64(float64(statsYear.BytesCombined) / 12.0)
	if statsYear.ExtrapolatedMonthlyCombinedRate != expectedYearExtra {
		t.Errorf("Year Extrapolated: got %d, want %d (BytesCombined / 12)", statsYear.ExtrapolatedMonthlyCombinedRate, expectedYearExtra)
	}
}

func TestGetTrafficStats_EdgeCases(t *testing.T) {
	appCtx := setupTestDB(t)

	originalTimeNow := timeNowFunc // Save current time function from main package
	timeNowFunc = mockTimeNow      // Override with mock
	t.Cleanup(func() { timeNowFunc = originalTimeNow }) // Restore original time function

	const iface = "eth2"
	daysInCurrentActualMonth := float64(time.Date(testNow.Year(), testNow.Month()+1, 0, 0, 0, 0, 0, testNow.Location()).Day()) // July has 31 days


	// --- Zero Traffic ---
	stats, err := getTrafficStats(appCtx, iface, "day")
	if err != nil {t.Fatalf("getTrafficStats failed for zero traffic: %v", err)}
	if stats.BytesCombined != 0 {t.Errorf("ZeroTraffic BytesCombined: got %d, want 0", stats.BytesCombined)}
	if stats.ExtrapolatedMonthlyCombinedRate != 0 {t.Errorf("ZeroTraffic Extrapolated: got %d, want 0", stats.ExtrapolatedMonthlyCombinedRate)}
	expectedHumanExtrapolated := "0 B (no data in period)"
	if stats.HumanExtrapolatedMonthlyCombinedRate != expectedHumanExtrapolated {
		t.Errorf("ZeroTraffic HumanExtrapolated: got %q, want %q", stats.HumanExtrapolatedMonthlyCombinedRate, expectedHumanExtrapolated)
	}

	// --- Very Small Traffic (testing "hour" case) ---
	addTrafficRecord(t, appCtx, testNow.Add(-1*time.Minute), iface, 1, 1, 2) // 2 Bytes
	statsSmall, err := getTrafficStats(appCtx, iface, "hour")
	if err != nil {t.Fatalf("getTrafficStats failed for small traffic: %v", err)}
	if statsSmall.BytesCombined != 2 {t.Errorf("SmallTraffic BytesCombined: got %d, want 2", statsSmall.BytesCombined)}
	
	durationHour := 1.0/24.0
	expectedSmallExtra := uint64((float64(statsSmall.BytesCombined) / durationHour) * daysInCurrentActualMonth)
	if statsSmall.ExtrapolatedMonthlyCombinedRate != expectedSmallExtra {
		t.Errorf("SmallTraffic Extrapolated: got %d, want %d", statsSmall.ExtrapolatedMonthlyCombinedRate, expectedSmallExtra)
	}
	if statsSmall.HumanExtrapolatedMonthlyCombinedRate != humanReadableSize(expectedSmallExtra) {
		t.Errorf("SmallTraffic HumanExtrapolated: got %q, want %q", statsSmall.HumanExtrapolatedMonthlyCombinedRate, humanReadableSize(expectedSmallExtra))
	}
}

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{name: "less than 1 second", duration: 500 * time.Millisecond, expected: "1 second"}, // Corrected: "1 seconds" to "1 second"
		{name: "less than 0.5 second", duration: 400 * time.Millisecond, expected: "0 seconds"},
		{name: "only seconds", duration: 30 * time.Second, expected: "30 seconds"},
		{name: "seconds rounding up", duration: 30*time.Second + 600*time.Millisecond, expected: "31 seconds"},
		{name: "seconds rounding down", duration: 30*time.Second + 400*time.Millisecond, expected: "30 seconds"},
		{name: "minutes and seconds", duration: 2*time.Minute + 30*time.Second, expected: "2 minutes 30 seconds"},
		{name: "hours minutes and seconds", duration: 1*time.Hour + 2*time.Minute + 30*time.Second, expected: "1 hour 2 minutes 30 seconds"},
		{name: "days hours minutes and seconds", duration: 2*24*time.Hour + 3*time.Hour + 4*time.Minute + 5*time.Second, expected: "2 days 3 hours 4 minutes 5 seconds"},
		{name: "hours and seconds (zero minutes)", duration: 1*time.Hour + 5*time.Second, expected: "1 hour 5 seconds"},
		{name: "days and minutes (zero hours and seconds)", duration: 1*24*time.Hour + 5*time.Minute, expected: "1 day 5 minutes"},
		{name: "exactly zero", duration: 0 * time.Second, expected: "0 seconds"},
		{name: "1 day", duration: 1 * 24 * time.Hour, expected: "1 day"},
		{name: "1 hour", duration: 1 * time.Hour, expected: "1 hour"},
		{name: "1 minute", duration: 1 * time.Minute, expected: "1 minute"},
		{name: "59 seconds", duration: 59 * time.Second, expected: "59 seconds"},
		{name: "59 minutes 59 seconds", duration: 59*time.Minute + 59*time.Second, expected: "59 minutes 59 seconds"},
		{name: "23 hours 59 minutes 59 seconds", duration: 23*time.Hour + 59*time.Minute + 59*time.Second, expected: "23 hours 59 minutes 59 seconds"},
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
