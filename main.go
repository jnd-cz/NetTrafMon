package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings" // Added for strings.Join
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/prometheus/procfs"
)

const (
	Version   = "1.0.0"
	DBPath    = "traffic.db"
	LogPath   = "netmonitor.log"
	CollectInterval = 60 // seconds
	SlidingWindowDays = 7 // Previously 30
	SQLDateTimeFormat = "2006-01-02 15:04:05"
)

type NetworkTraffic struct {
	Timestamp      time.Time
	Interface      string
	BytesReceived  uint64
	BytesSent      uint64
	BytesCombined  uint64
}

type TrafficStats struct {
	Interface       string    `json:"interface"`
	TimeRange       string    `json:"time_range"`
	BytesReceived   uint64    `json:"bytes_received"`
	BytesSent       uint64    `json:"bytes_sent"`
	BytesCombined   uint64    `json:"bytes_combined"`
	HumanReceived   string    `json:"human_received"`
	HumanSent       string    `json:"human_sent"`
	HumanCombined   string    `json:"human_combined"`
	ExtrapolatedMonthlyCombinedRate uint64 `json:"extrapolated_monthly_combined_rate"`
	HumanExtrapolatedMonthlyCombinedRate string `json:"human_extrapolated_monthly_combined_rate"`
}

type MonthEstimate struct {
	Interface     string  `json:"interface"`
	EstimatedData uint64  `json:"estimated_data_bytes"`
	HumanEstimated string `json:"human_estimated"`
}

type SystemInfo struct {
	Version   string `json:"version"`
	Uptime    string `json:"uptime"`
	Hostname  string `json:"hostname"`
}

type AppResponse struct {
	SystemInfo    SystemInfo               `json:"system_info"`
	CurrentStats  map[string]TrafficStats  `json:"current_stats"`
	HistoryStats  map[string][]TrafficStats `json:"history_stats"`
	MonthEstimates []MonthEstimate         `json:"month_estimates"`
}

var (
	timeNowFunc = time.Now // Remains global for test mockability
)

type AppContext struct {
	DB               *sql.DB
	Logger           *log.Logger
	Interfaces       []string
	LastBytes        map[string]map[string]uint64
	EffectiveDBPath  string
	EffectiveLogPath string
	StartTime        time.Time
	AppVersion       string
}

// TimeRangeSpec defines the properties and calculation logic for a specific time range.
type TimeRangeSpec struct {
	DisplayName             string
	QuerySince              func(now time.Time) time.Time
	QueryUntil              func(now time.Time) *time.Time // Pointer to allow nil
	CalculateDurationDays   func(now time.Time, actualStart time.Time, actualEnd time.Time) float64
	IsFixedPeriod           bool // True for periods like "previous_month" or "last_30_days" where extrapolation means total data.
	IsRateBasedExtrapolation bool // True for periods like "hour", "day", "week" where rate is used for monthly extrapolation.
	IsAnnualAverage         bool // True for "year" where monthly average is calculated.
}

var timeRangeSpecs = map[string]TimeRangeSpec{
	"hour": {
		DisplayName: "Last Hour",
		QuerySince:  func(now time.Time) time.Time { return now.Add(-time.Hour) },
		QueryUntil:  nil,
		CalculateDurationDays: func(now time.Time, actualStart time.Time, actualEnd time.Time) float64 {
			return 1.0 / 24.0
		},
		IsRateBasedExtrapolation: true,
	},
	"day": {
		DisplayName: "Last 24 Hours",
		QuerySince:  func(now time.Time) time.Time { return now.AddDate(0, 0, -1) },
		QueryUntil:  nil,
		CalculateDurationDays: func(now time.Time, actualStart time.Time, actualEnd time.Time) float64 {
			return 1.0
		},
		IsRateBasedExtrapolation: true,
	},
	"week": {
		DisplayName: "Last 7 Days",
		QuerySince:  func(now time.Time) time.Time { return now.AddDate(0, 0, -7) },
		QueryUntil:  nil,
		CalculateDurationDays: func(now time.Time, actualStart time.Time, actualEnd time.Time) float64 {
			return 7.0
		},
		IsRateBasedExtrapolation: true,
	},
	"month": { // Represents "Last 30 Days"
		DisplayName: "Last 30 Days",
		QuerySince:  func(now time.Time) time.Time { return now.AddDate(0, 0, -30) },
		QueryUntil:  nil,
		CalculateDurationDays: func(now time.Time, actualStart time.Time, actualEnd time.Time) float64 {
			return 30.0
		},
		IsFixedPeriod: true,
	},
	"previous_month": {
		DisplayName: "Previous Month", // Will be formatted dynamically
		QuerySince: func(now time.Time) time.Time {
			return time.Date(now.Year(), now.Month()-1, 1, 0, 0, 0, 0, now.Location())
		},
		QueryUntil: func(now time.Time) *time.Time {
			t := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).Add(-time.Nanosecond)
			return &t
		},
		CalculateDurationDays: func(now time.Time, actualStart time.Time, actualEnd time.Time) float64 {
			// actualStart for previous_month is the first day of that month.
			return float64(time.Date(actualStart.Year(), actualStart.Month()+1, 0, 0, 0, 0, 0, actualStart.Location()).Day())
		},
		IsFixedPeriod: true,
	},
	"year": {
		DisplayName: "Last Year",
		QuerySince:  func(now time.Time) time.Time { return now.AddDate(-1, 0, 0) },
		QueryUntil:  nil,
		CalculateDurationDays: func(now time.Time, actualStart time.Time, actualEnd time.Time) float64 {
			// Calculate actual days in the last year period, considering leap year
			// For simplicity in this example, we'll use the same logic as before.
			// A more precise CalculateDurationDays could use actualStart and actualEnd if available from DB.
			if now.Year()%4 == 0 && (now.Year()%100 != 0 || now.Year()%400 == 0) {
				return 366.0
			}
			return 365.0
		},
		IsAnnualAverage: true,
	},
}

func humanReadableSize(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func formatUptime(d time.Duration) string {
	// Round seconds to the nearest whole number
	seconds := int(d.Seconds() + 0.5)

	days := seconds / (24 * 3600)
	seconds %= (24 * 3600)
	hours := seconds / 3600
	seconds %= 3600
	minutes := seconds / 60
	seconds %= 60

	var parts []string
	if days > 0 {
		if days == 1 {
			parts = append(parts, "1 day")
		} else {
			parts = append(parts, fmt.Sprintf("%d days", days))
		}
	}
	if hours > 0 || (days == 0 && hours > 0) { // Added condition to include hours if days is 0 but hours > 0
		if hours == 1 {
			parts = append(parts, "1 hour")
		} else {
			parts = append(parts, fmt.Sprintf("%d hours", hours))
		}
	}
	if minutes > 0 || (days == 0 && hours == 0 && minutes > 0) { // Added condition to include minutes if days and hours are 0 but minutes > 0
		if minutes == 1 {
			parts = append(parts, "1 minute")
		} else {
			parts = append(parts, fmt.Sprintf("%d minutes", minutes))
		}
	}
	// Always include seconds if it's the only unit or if other units are present
	if seconds > 0 || (days == 0 && hours == 0 && minutes == 0) {
		if seconds == 1 {
			parts = append(parts, "1 second")
		} else {
			parts = append(parts, fmt.Sprintf("%d seconds", seconds))
		}
	}

	if len(parts) == 0 {
		return "0 seconds" // Handle case where duration is less than a second and rounds to 0
	}

	// Join parts with spaces, but this might not be the most natural way to read it.
	// Consider a more sophisticated joining logic if needed.
	// For now, simple space join.
	// var result string
	// for i, p := range parts {
	// 	if i > 0 {
	// 		result += " "
	// 	}
	// 	result += p
	// }
	// return result
	return strings.Join(parts, " ")
}

func setupLogger(appCtx *AppContext) {
	// Create log directory if it doesn't exist
	logDir := filepath.Dir(appCtx.EffectiveLogPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		// Use a more general log output if appCtx.Logger is not yet initialized
		log.Fatalf("Failed to create log directory: %v", err)
	}

	// Open log file
	logFile, err := os.OpenFile(appCtx.EffectiveLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	appCtx.Logger = log.New(logFile, "NETMONITOR: ", log.Ldate|log.Ltime|log.Lshortfile)
	appCtx.Logger.Println("Logger initialized")
}

func initDB(appCtx *AppContext) {
	// Create database directory if it doesn't exist
	dbDir := filepath.Dir(appCtx.EffectiveDBPath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		appCtx.Logger.Fatalf("Failed to create database directory: %v", err)
	}

	var err error
	appCtx.DB, err = sql.Open("sqlite3", appCtx.EffectiveDBPath)
	if err != nil {
		appCtx.Logger.Fatalf("Failed to open database: %v", err)
	}

	// Create tables if they don't exist
	_, err = appCtx.DB.Exec(`CREATE TABLE IF NOT EXISTS network_traffic (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME,
		interface TEXT,
		bytes_received INTEGER,
		bytes_sent INTEGER,
		bytes_combined INTEGER
	)`)
	if err != nil {
		appCtx.Logger.Fatalf("Failed to create table: %v", err)
	}

	// Create index for faster queries
	_, err = appCtx.DB.Exec(`CREATE INDEX IF NOT EXISTS idx_network_traffic_timestamp ON network_traffic(timestamp)`)
	if err != nil {
		appCtx.Logger.Fatalf("Failed to create index: %v", err)
	}
	
	_, err = appCtx.DB.Exec(`CREATE INDEX IF NOT EXISTS idx_network_traffic_interface ON network_traffic(interface)`)
	if err != nil {
		appCtx.Logger.Fatalf("Failed to create index: %v", err)
	}

	appCtx.Logger.Println("Database initialized")
}

func detectInterfaces(appCtx *AppContext) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		appCtx.Logger.Fatalf("Failed to access procfs: %v", err)
	}

	netStats, err := fs.NetDev()
	if err != nil {
		appCtx.Logger.Fatalf("Failed to get network statistics: %v", err)
	}

	appCtx.Interfaces = make([]string, 0)
	appCtx.LastBytes = make(map[string]map[string]uint64)

	for _, stat := range netStats {
		// Skip loopback and virtual interfaces
		if stat.Name == "lo" || stat.Name == "docker0" || stat.Name == "veth" {
			continue
		}
		appCtx.Interfaces = append(appCtx.Interfaces, stat.Name)
		appCtx.LastBytes[stat.Name] = map[string]uint64{
			"rx": stat.RxBytes,
			"tx": stat.TxBytes,
		}
	}

	appCtx.Logger.Printf("Detected interfaces: %v", appCtx.Interfaces)
}

func collectTraffic(appCtx *AppContext) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		appCtx.Logger.Printf("Failed to access procfs: %v", err)
		return
	}

	netStats, err := fs.NetDev()
	if err != nil {
		appCtx.Logger.Printf("Failed to get network statistics: %v", err)
		return
	}

	timestamp := timeNowFunc() // Assuming timeNowFunc remains global for mockability

	for _, stat := range netStats {
		if _, ok := appCtx.LastBytes[stat.Name]; !ok {
			// New interface detected, skip this round
			appCtx.LastBytes[stat.Name] = map[string]uint64{
				"rx": stat.RxBytes,
				"tx": stat.TxBytes,
			}
			continue
		}

		// Calculate delta since last check
		rxDelta := uint64(0)
		txDelta := uint64(0)

		// If current value is less than previous value, system might have restarted
		// or counter overflowed
		if stat.RxBytes >= appCtx.LastBytes[stat.Name]["rx"] {
			rxDelta = stat.RxBytes - appCtx.LastBytes[stat.Name]["rx"]
		} else {
			appCtx.Logger.Printf("Counter reset detected for %s (RX), previous: %d, current: %d",
				stat.Name, appCtx.LastBytes[stat.Name]["rx"], stat.RxBytes)
			rxDelta = stat.RxBytes
		}

		if stat.TxBytes >= appCtx.LastBytes[stat.Name]["tx"] {
			txDelta = stat.TxBytes - appCtx.LastBytes[stat.Name]["tx"]
		} else {
			appCtx.Logger.Printf("Counter reset detected for %s (TX), previous: %d, current: %d",
				stat.Name, appCtx.LastBytes[stat.Name]["tx"], stat.TxBytes)
			txDelta = stat.TxBytes
		}

		// Update last known values
		appCtx.LastBytes[stat.Name]["rx"] = stat.RxBytes
		appCtx.LastBytes[stat.Name]["tx"] = stat.TxBytes

		// Skip if no traffic
		if rxDelta == 0 && txDelta == 0 {
			continue
		}

		// Store in database
		_, err = appCtx.DB.Exec(
			"INSERT INTO network_traffic (timestamp, interface, bytes_received, bytes_sent, bytes_combined) VALUES (?, ?, ?, ?, ?)",
			timestamp.Format(SQLDateTimeFormat),
			stat.Name,
			rxDelta,
			txDelta,
			rxDelta+txDelta,
		)
		if err != nil {
			appCtx.Logger.Printf("Failed to insert traffic data: %v", err)
		}
	}
}

func cleanupOldData(appCtx *AppContext) {
	// Keep data for one year
	oneYearAgo := timeNowFunc().AddDate(-1, 0, 0).Format(SQLDateTimeFormat)

	result, err := appCtx.DB.Exec("DELETE FROM network_traffic WHERE timestamp < ?", oneYearAgo)
	if err != nil {
		appCtx.Logger.Printf("Failed to clean up old data: %v", err)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		appCtx.Logger.Printf("Cleaned up %d old records", rowsAffected)
	}
}

func getTrafficStats(appCtx *AppContext, interfaceName, timeRangeKey string) (TrafficStats, error) {
	now := timeNowFunc() // Assuming timeNowFunc remains global
	spec, ok := timeRangeSpecs[timeRangeKey]
	if !ok {
		return TrafficStats{}, fmt.Errorf("invalid time range key: %s", timeRangeKey)
	}

	var query string
	var args []interface{}
	actualTimeRange := spec.DisplayName

	since := spec.QuerySince(now)
	args = append(args, interfaceName, since.Format(SQLDateTimeFormat))

	if spec.QueryUntil != nil {
		until := spec.QueryUntil(now)
		query = `
			SELECT SUM(bytes_received), SUM(bytes_sent), SUM(bytes_combined)
			FROM network_traffic
			WHERE interface = ? AND timestamp >= ? AND timestamp <= ?`
		args = append(args, (*until).Format(SQLDateTimeFormat))
		if timeRangeKey == "previous_month" { // Dynamic display name for previous_month
			actualTimeRange = fmt.Sprintf("Previous Month (%s)", spec.QuerySince(now).Format("January 2006"))
		}
	} else {
		query = `
			SELECT SUM(bytes_received), SUM(bytes_sent), SUM(bytes_combined)
			FROM network_traffic
			WHERE interface = ? AND timestamp >= ?`
	}

	var bytesReceived, bytesSent, bytesCombined sql.NullInt64
	// For CalculateDurationDays, we pass `since` as actualStart.
	// For ranges with QueryUntil, actualEnd would be `*spec.QueryUntil(now)`.
	// This part might need refinement if CalculateDurationDays needs more precise DB timestamps.
	// For now, QuerySince(now) is a good proxy for actualStart for most CalculateDurationDays implementations.
	err := appCtx.DB.QueryRow(query, args...).Scan(&bytesReceived, &bytesSent, &bytesCombined)
	if err != nil {
		// Log error but return zero stats to avoid breaking the entire response
		appCtx.Logger.Printf("Failed to query traffic stats for %s, range %s: %v", interfaceName, timeRangeKey, err)
		// Return zeroed stats but with the correct interface and time range labels
		return TrafficStats{
			Interface:      interfaceName,
			TimeRange:      actualTimeRange, // Use potentially formatted actualTimeRange
			HumanReceived:  humanReadableSize(0),
			HumanSent:      humanReadableSize(0),
			HumanCombined:  humanReadableSize(0),
			HumanExtrapolatedMonthlyCombinedRate: humanReadableSize(0) + " (based on 0 data)",
		}, nil // Return nil error to allow other stats to load
	}

	var rxBytes, txBytes, totalBytes uint64
	if bytesReceived.Valid {
		rxBytes = uint64(bytesReceived.Int64)
	}
	if bytesSent.Valid {
		txBytes = uint64(bytesSent.Int64)
	}
	if bytesCombined.Valid {
		totalBytes = uint64(bytesCombined.Int64)
	}

	var extrapolatedRate uint64
	// actualStart for CalculateDurationDays is `since`
	// actualEnd would be `*spec.QueryUntil(now)` if not nil, or `now` otherwise.
	// This simplification assumes CalculateDurationDays can work with `now` for non-QueryUntil ranges.
	var actualEndForDurationCalc time.Time
	if spec.QueryUntil != nil {
		actualEndForDurationCalc = *spec.QueryUntil(now)
	} else {
		actualEndForDurationCalc = now
	}
	durationDays := spec.CalculateDurationDays(now, since, actualEndForDurationCalc)

	if spec.IsRateBasedExtrapolation {
		daysInCurrentMonth := float64(time.Date(now.Year(), now.Month()+1, 0, 0, 0, 0, 0, now.Location()).Day())
		if durationDays > 0 && totalBytes > 0 {
			extrapolatedRate = uint64((float64(totalBytes) / durationDays) * daysInCurrentMonth)
		} else {
			extrapolatedRate = 0
		}
	} else if spec.IsFixedPeriod {
		extrapolatedRate = totalBytes
	} else if spec.IsAnnualAverage {
		if totalBytes > 0 {
			extrapolatedRate = uint64(float64(totalBytes) / 12.0) // Average monthly from annual
		} else {
			extrapolatedRate = 0
		}
	}

	humanExtrapolatedRate := humanReadableSize(extrapolatedRate)
	if totalBytes == 0 {
		humanExtrapolatedRate = humanReadableSize(0) + " (no data in period)"
	} else if !spec.IsFixedPeriod && !spec.IsAnnualAverage && durationDays <= 0 { // Rate-based but invalid duration
		humanExtrapolatedRate = "N/A (invalid duration for rate)"
	}

	return TrafficStats{
		Interface:      interfaceName,
		TimeRange:      actualTimeRange, // Use potentially formatted actualTimeRange
		BytesReceived:  rxBytes,
		BytesSent:      txBytes,
		BytesCombined:  totalBytes,
		HumanReceived:  humanReadableSize(rxBytes),
		HumanSent:      humanReadableSize(txBytes),
		HumanCombined:  humanReadableSize(totalBytes),
		ExtrapolatedMonthlyCombinedRate: extrapolatedRate,
		HumanExtrapolatedMonthlyCombinedRate: humanExtrapolatedRate,
	}, nil
}

// calculateDaysInMonth returns the number of days in the month of the given time.
func calculateDaysInMonth(t time.Time) int {
	return time.Date(t.Year(), t.Month()+1, 0, 0, 0, 0, 0, t.Location()).Day()
}

// calculateHourlyRate calculates the hourly traffic rate for a given interface.
// It tries a sliding window first, then falls back to all data if necessary.
func calculateHourlyRate(appCtx *AppContext, interfaceName string, now time.Time, useSlidingWindow bool) (rate float64, actualHours float64, periodText string, err error) {
	if useSlidingWindow {
		// Attempt sliding window calculation
		slidingWindowStartDate := now.AddDate(0, 0, -SlidingWindowDays)
		var slidingWindowTotalBytes sql.NullInt64
		var slidingWindowMinTimestamp, slidingWindowMaxTimestamp sql.NullString

		dbErr := appCtx.DB.QueryRow(`
			SELECT SUM(bytes_combined), MIN(timestamp), MAX(timestamp)
			FROM network_traffic
			WHERE interface = ? AND timestamp >= ?
		`, interfaceName, slidingWindowStartDate.Format(SQLDateTimeFormat)).Scan(
			&slidingWindowTotalBytes, &slidingWindowMinTimestamp, &slidingWindowMaxTimestamp,
		)

		if dbErr == nil && slidingWindowTotalBytes.Valid && slidingWindowTotalBytes.Int64 > 0 && slidingWindowMinTimestamp.Valid && slidingWindowMaxTimestamp.Valid {
			minTime, errMin := time.Parse(SQLDateTimeFormat, slidingWindowMinTimestamp.String)
			maxTime, errMax := time.Parse(SQLDateTimeFormat, slidingWindowMaxTimestamp.String)

			if errMin == nil && errMax == nil {
				durationHours := maxTime.Sub(minTime).Hours()
				if durationHours >= 0.25 { // At least 15 minutes of actual data
					rate = float64(slidingWindowTotalBytes.Int64) / durationHours
					actualHours = durationHours
					if durationHours < 24 {
						periodText = fmt.Sprintf("last %d days (%.1f hours actual data)", SlidingWindowDays, durationHours)
					} else {
						periodText = fmt.Sprintf("last %d days (%.1f days actual data)", SlidingWindowDays, durationHours/24)
					}
					appCtx.Logger.Printf("calculateHourlyRate for %s: Using sliding window (last %d days, %.2f hours actual data) for rate calculation.", interfaceName, SlidingWindowDays, durationHours)
					return rate, actualHours, periodText, nil
				}
			}
		}
		appCtx.Logger.Printf("calculateHourlyRate for %s: Sliding window data insufficient or error (%v), falling back to all data.", interfaceName, dbErr)
	}

	// Fallback to all data
	var earliestTimestamp string
	errDb := appCtx.DB.QueryRow(`
		SELECT MIN(timestamp) 
		FROM network_traffic 
		WHERE interface = ?
	`, interfaceName).Scan(&earliestTimestamp)

	if errDb != nil || earliestTimestamp == "" {
		appCtx.Logger.Printf("calculateHourlyRate for %s: No data available (MIN(timestamp) query error: %v, or empty).", interfaceName, errDb)
		return 0, 0, "No data available", nil // Return 0 rate, no error to signal no data
	}

	earliestTime, errParse := time.Parse(SQLDateTimeFormat, earliestTimestamp)
	if errParse != nil {
		appCtx.Logger.Printf("calculateHourlyRate for %s: Failed to parse earliest timestamp %s: %v", interfaceName, earliestTimestamp, errParse)
		return 0, 0, "", fmt.Errorf("failed to parse earliest timestamp: %w", errParse)
	}

	totalTimeSpanAllData := now.Sub(earliestTime).Hours()
	if totalTimeSpanAllData < 0.25 { // Less than 15 minutes of data overall
		appCtx.Logger.Printf("calculateHourlyRate for %s: Insufficient data overall (%.2f hours).", interfaceName, totalTimeSpanAllData)
		return 0, 0, "Insufficient data (< 15 minutes total)", nil // Return 0 rate
	}

	var totalBytesAllTime sql.NullInt64
	errDb = appCtx.DB.QueryRow(`
		SELECT SUM(bytes_combined) 
		FROM network_traffic 
		WHERE interface = ?
	`, interfaceName).Scan(&totalBytesAllTime)

	if errDb != nil || !totalBytesAllTime.Valid || totalBytesAllTime.Int64 == 0 {
		appCtx.Logger.Printf("calculateHourlyRate for %s: No traffic recorded (SUM query error: %v, or zero bytes).", interfaceName, errDb)
		return 0, 0, "No traffic recorded", nil // Return 0 rate
	}

	rate = float64(totalBytesAllTime.Int64) / totalTimeSpanAllData
	actualHours = totalTimeSpanAllData
	if totalTimeSpanAllData < 1.0 {
		periodText = fmt.Sprintf("%.0f min (all data)", totalTimeSpanAllData*60)
	} else if totalTimeSpanAllData < 24.0 {
		periodText = fmt.Sprintf("%.1f hours (all data)", totalTimeSpanAllData)
	} else {
		periodText = fmt.Sprintf("%.1f days (all data)", totalTimeSpanAllData/24)
	}
	appCtx.Logger.Printf("calculateHourlyRate for %s: Using all available data (%.1f hours) for rate calculation.", interfaceName, totalTimeSpanAllData)
	return rate, actualHours, periodText, nil
}

func getMonthEstimate(appCtx *AppContext, interfaceName string) (MonthEstimate, error) {
	now := timeNowFunc() // Assuming timeNowFunc remains global
	startOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	daysInMonth := float64(calculateDaysInMonth(now))

	daysPassed := now.Sub(startOfMonth).Hours() / 24
	daysRemaining := daysInMonth - daysPassed

	hourlyRate, timespanForRateCalculationHours, timespanText, err := calculateHourlyRate(appCtx, interfaceName, now, true)
	if err != nil {
		// This error is from parsing in calculateHourlyRate, critical.
		return MonthEstimate{}, err
	}

	if hourlyRate == 0 { // Indicates no data or insufficient data from calculateHourlyRate
		return MonthEstimate{
			Interface:      interfaceName,
			EstimatedData:  0,
			HumanEstimated: timespanText, // timespanText will contain "No data available" or "Insufficient data"
		}, nil
	}

	// Get current month data if available
	var monthToDateBytes sql.NullInt64
	dbErr := appCtx.DB.QueryRow(`
		SELECT SUM(bytes_combined) 
		FROM network_traffic 
		WHERE interface = ? AND timestamp >= ?
	`, interfaceName, startOfMonth.Format(SQLDateTimeFormat)).Scan(&monthToDateBytes)
	
	var actualMonthBytes uint64
	if dbErr == nil && monthToDateBytes.Valid {
		actualMonthBytes = uint64(monthToDateBytes.Int64)
	}
	
	// Calculate monthly estimate
	var estimatedBytes uint64
	var estimateDescription string
	
	if daysPassed < 1.0 || actualMonthBytes == 0 {
		// Beginning of month or no month data yet - estimate entire month
		estimatedBytes = uint64(hourlyRate * 24.0 * daysInMonth)
		estimateDescription = fmt.Sprintf("(full month estimate, rate based on %s)", timespanText)
	} else {
		// Mid-month with some data - use actual data plus estimate for remaining days
		remainingEstimate := uint64(hourlyRate * 24.0 * daysRemaining)
		estimatedBytes = actualMonthBytes + remainingEstimate
		estimateDescription = fmt.Sprintf("(%s actual + %s estimate for remaining days, rate based on %s)", 
			humanReadableSize(actualMonthBytes), 
			humanReadableSize(remainingEstimate), 
			timespanText)
	}
	
	// Add confidence level based on data span length
	// Use timespanForRateCalculationHours which reflects the actual data period used for rate.
	if timespanForRateCalculationHours < 1.0 { // Less than 1 hour of data for rate
		estimateDescription += " [low confidence]"
	} else if timespanForRateCalculationHours >= 1.0 && timespanForRateCalculationHours < 24.0 { // 1 to 24 hours of data for rate
		estimateDescription += " [medium confidence]"
	} else { // 24+ hours of data for rate
		estimateDescription += " [high confidence]"
	}

	return MonthEstimate{
		Interface:      interfaceName,
		EstimatedData:  estimatedBytes,
		HumanEstimated: humanReadableSize(estimatedBytes) + " " + estimateDescription,
	}, nil
}

func getApplicationData(appCtx *AppContext) (AppResponse, error) {
	hostname, err := os.Hostname()
	if err != nil {
		appCtx.Logger.Printf("Failed to get hostname: %v", err)
		hostname = "unknown" // Fallback hostname
	}

	uptime := formatUptime(timeNowFunc().Sub(appCtx.StartTime)) // Use appCtx.StartTime

	sysInfo := SystemInfo{
		Version:  appCtx.AppVersion, // Use appCtx.AppVersion
		Uptime:   uptime,
		Hostname: hostname,
	}

	currentStats := make(map[string]TrafficStats)
	historyStats := make(map[string][]TrafficStats)
	monthEstimates := make([]MonthEstimate, 0)

	timeRanges := []string{"hour", "day", "week", "month", "previous_month", "year"}

	for _, iface := range appCtx.Interfaces { // Use appCtx.Interfaces
		for _, tr := range timeRanges {
			stats, err := getTrafficStats(appCtx, iface, tr) // Pass appCtx
			if err != nil {
				appCtx.Logger.Printf("Failed to get %s stats for %s: %v", tr, iface, err)
			} else {
				if tr == "hour" {
					currentStats[iface] = stats
				}
				historyStats[iface] = append(historyStats[iface], stats)
			}
		}

		estimate, err := getMonthEstimate(appCtx, iface) // Pass appCtx
		if err != nil {
			appCtx.Logger.Printf("Failed to get month estimate for %s: %v", iface, err)
		} else {
			monthEstimates = append(monthEstimates, estimate)
		}
	}

	return AppResponse{
		SystemInfo:    sysInfo,
		CurrentStats:  currentStats,
		HistoryStats:  historyStats,
		MonthEstimates: monthEstimates,
	}, nil
}

func collectRoutine(appCtx *AppContext) {
	ticker := time.NewTicker(time.Duration(CollectInterval) * time.Second)
	defer ticker.Stop()

	cleanupTicker := time.NewTicker(24 * time.Hour)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ticker.C:
			collectTraffic(appCtx)
		case <-cleanupTicker.C:
			cleanupOldData(appCtx)
		}
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request, appCtx *AppContext) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": appCtx.AppVersion})
}

func handleMetrics(w http.ResponseWriter, r *http.Request, appCtx *AppContext) {
	w.Header().Set("Content-Type", "application/json")

	appData, err := getApplicationData(appCtx) // Pass appCtx
	if err != nil {
		appCtx.Logger.Printf("Error getting application data for /metrics: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(appData)
}

func handleRoot(w http.ResponseWriter, r *http.Request, appCtx *AppContext) {
	tmpl, err := template.ParseFiles("index.html")
	if err != nil {
		appCtx.Logger.Printf("Error parsing HTML template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	appData, err := getApplicationData(appCtx)
	if err != nil {
		appCtx.Logger.Printf("Error getting application data for /: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, appData)
}

func startWebServer(appCtx *AppContext) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleRoot(w, r, appCtx)
	})
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		handleMetrics(w, r, appCtx)
	})
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		handleHealth(w, r, appCtx)
	})

	appCtx.Logger.Println("Starting web server on :8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		appCtx.Logger.Fatalf("Failed to start web server: %v", err)
	}
}

func main() {
	appCtx := &AppContext{
		AppVersion: Version,
		StartTime:  timeNowFunc(),
	}

	// Determine effective paths
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get current working directory: %v", err) // Use standard log if logger not set
	}

	envDBPath := os.Getenv("NETMONITOR_DB_PATH")
	if envDBPath != "" {
		appCtx.EffectiveDBPath = envDBPath
	} else {
		appCtx.EffectiveDBPath = filepath.Join(cwd, DBPath)
	}

	envLogPath := os.Getenv("NETMONITOR_LOG_PATH")
	if envLogPath != "" {
		appCtx.EffectiveLogPath = envLogPath
	} else {
		appCtx.EffectiveLogPath = filepath.Join(cwd, LogPath)
	}

	// Setup logger
	setupLogger(appCtx)

	// Initialize the database
	initDB(appCtx)
	defer appCtx.DB.Close()

	// Detect network interfaces
	detectInterfaces(appCtx)

	// Start data collection in a goroutine
	go collectRoutine(appCtx)

	// Start web server in a goroutine
	go startWebServer(appCtx)

	// Wait for termination signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	
	appCtx.Logger.Println("Shutting down...")
}
