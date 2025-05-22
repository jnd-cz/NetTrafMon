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
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/prometheus/procfs"
)

const (
	Version   = "1.0.0"
	DBPath    = "/var/lib/netmonitor/traffic.db"
	LogPath   = "/var/log/netmonitor/netmonitor.log"
	CollectInterval = 60 // seconds
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
	db          *sql.DB
	startTime   time.Time
	interfaces  []string
	lastBytes   map[string]map[string]uint64 // interface -> direction -> bytes
	logger      *log.Logger
)

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
		parts = append(parts, fmt.Sprintf("%d days", days))
	}
	if hours > 0 || (days == 0 && hours > 0) { // Added condition to include hours if days is 0 but hours > 0
		parts = append(parts, fmt.Sprintf("%d hours", hours))
	}
	if minutes > 0 || (days == 0 && hours == 0 && minutes > 0) { // Added condition to include minutes if days and hours are 0 but minutes > 0
		parts = append(parts, fmt.Sprintf("%d minutes", minutes))
	}
	// Always include seconds if it's the only unit or if other units are present
	if seconds > 0 || (days == 0 && hours == 0 && minutes == 0) {
		parts = append(parts, fmt.Sprintf("%d seconds", seconds))
	}

	if len(parts) == 0 {
		return "0 seconds" // Handle case where duration is less than a second and rounds to 0
	}

	// Join parts with spaces, but this might not be the most natural way to read it.
	// Consider a more sophisticated joining logic if needed.
	// For now, simple space join.
	var result string
	for i, p := range parts {
		if i > 0 {
			result += " "
		}
		result += p
	}
	return result
}

func setupLogger() {
	// Create log directory if it doesn't exist
	logDir := filepath.Dir(LogPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Fatalf("Failed to create log directory: %v", err)
	}
	
	// Open log file
	logFile, err := os.OpenFile(LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	
	logger = log.New(logFile, "NETMONITOR: ", log.Ldate|log.Ltime|log.Lshortfile)
	logger.Println("Logger initialized")
}

func initDB() {
	// Create database directory if it doesn't exist
	dbDir := filepath.Dir(DBPath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		logger.Fatalf("Failed to create database directory: %v", err)
	}

	var err error
	db, err = sql.Open("sqlite3", DBPath)
	if err != nil {
		logger.Fatalf("Failed to open database: %v", err)
	}

	// Create tables if they don't exist
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS network_traffic (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME,
		interface TEXT,
		bytes_received INTEGER,
		bytes_sent INTEGER,
		bytes_combined INTEGER
	)`)
	if err != nil {
		logger.Fatalf("Failed to create table: %v", err)
	}

	// Create index for faster queries
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_network_traffic_timestamp ON network_traffic(timestamp)`)
	if err != nil {
		logger.Fatalf("Failed to create index: %v", err)
	}
	
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_network_traffic_interface ON network_traffic(interface)`)
	if err != nil {
		logger.Fatalf("Failed to create index: %v", err)
	}

	logger.Println("Database initialized")
}

func detectInterfaces() {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		logger.Fatalf("Failed to access procfs: %v", err)
	}

	netStats, err := fs.NetDev()
	if err != nil {
		logger.Fatalf("Failed to get network statistics: %v", err)
	}

	interfaces = make([]string, 0)
	lastBytes = make(map[string]map[string]uint64)

	for _, stat := range netStats {
		// Skip loopback and virtual interfaces
		if stat.Name == "lo" || stat.Name == "docker0" || stat.Name == "veth" {
			continue
		}
		interfaces = append(interfaces, stat.Name)
		lastBytes[stat.Name] = map[string]uint64{
			"rx": stat.RxBytes,
			"tx": stat.TxBytes,
		}
	}

	logger.Printf("Detected interfaces: %v", interfaces)
}

func collectTraffic() {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		logger.Printf("Failed to access procfs: %v", err)
		return
	}

	netStats, err := fs.NetDev()
	if err != nil {
		logger.Printf("Failed to get network statistics: %v", err)
		return
	}

	timestamp := time.Now()

	for _, stat := range netStats {
		if _, ok := lastBytes[stat.Name]; !ok {
			// New interface detected, skip this round
			lastBytes[stat.Name] = map[string]uint64{
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
		if stat.RxBytes >= lastBytes[stat.Name]["rx"] {
			rxDelta = stat.RxBytes - lastBytes[stat.Name]["rx"]
		} else {
			logger.Printf("Counter reset detected for %s (RX), previous: %d, current: %d", 
                           stat.Name, lastBytes[stat.Name]["rx"], stat.RxBytes)
			rxDelta = stat.RxBytes
		}

		if stat.TxBytes >= lastBytes[stat.Name]["tx"] {
			txDelta = stat.TxBytes - lastBytes[stat.Name]["tx"]
		} else {
			logger.Printf("Counter reset detected for %s (TX), previous: %d, current: %d", 
                           stat.Name, lastBytes[stat.Name]["tx"], stat.TxBytes)
			txDelta = stat.TxBytes
		}

		// Update last known values
		lastBytes[stat.Name]["rx"] = stat.RxBytes
		lastBytes[stat.Name]["tx"] = stat.TxBytes

		// Skip if no traffic
		if rxDelta == 0 && txDelta == 0 {
			continue
		}

		// Store in database
		_, err = db.Exec(
			"INSERT INTO network_traffic (timestamp, interface, bytes_received, bytes_sent, bytes_combined) VALUES (?, ?, ?, ?, ?)",
			timestamp.Format("2006-01-02 15:04:05"),
			stat.Name,
			rxDelta,
			txDelta,
			rxDelta+txDelta,
		)
		if err != nil {
			logger.Printf("Failed to insert traffic data: %v", err)
		}
	}
}

func cleanupOldData() {
	// Keep data for one year
	oneYearAgo := time.Now().AddDate(-1, 0, 0).Format("2006-01-02 15:04:05")
	
	result, err := db.Exec("DELETE FROM network_traffic WHERE timestamp < ?", oneYearAgo)
	if err != nil {
		logger.Printf("Failed to clean up old data: %v", err)
		return
	}
	
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		logger.Printf("Cleaned up %d old records", rowsAffected)
	}
}

func getTrafficStats(interfaceName, timeRange string) (TrafficStats, error) {
	var query string
	var since time.Time
	
	now := time.Now()
	
	switch timeRange {
	case "hour":
		since = now.Add(-time.Hour)
	case "day":
		since = now.AddDate(0, 0, -1)
	case "week":
		since = now.AddDate(0, 0, -7)
	case "month":
		since = now.AddDate(0, -1, 0)
	case "year":
		since = now.AddDate(-1, 0, 0)
	default:
		return TrafficStats{}, fmt.Errorf("invalid time range: %s", timeRange)
	}
	
	query = `
		SELECT SUM(bytes_received), SUM(bytes_sent), SUM(bytes_combined) 
		FROM network_traffic 
		WHERE interface = ? AND timestamp >= ?
	`
	
	var bytesReceived, bytesSent, bytesCombined sql.NullInt64
	err := db.QueryRow(query, interfaceName, since.Format("2006-01-02 15:04:05")).Scan(
		&bytesReceived, &bytesSent, &bytesCombined,
	)
	if err != nil {
		return TrafficStats{}, err
	}
	
	// Convert nullable values to uint64
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
	
	return TrafficStats{
		Interface:      interfaceName,
		TimeRange:      timeRange,
		BytesReceived:  rxBytes,
		BytesSent:      txBytes,
		BytesCombined:  totalBytes,
		HumanReceived:  humanReadableSize(rxBytes),
		HumanSent:      humanReadableSize(txBytes),
		HumanCombined:  humanReadableSize(totalBytes),
	}, nil
}

func getMonthEstimate(interfaceName string) (MonthEstimate, error) {
	now := time.Now()
	startOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	
	// Calculate days in current month
	var daysInMonth float64
	if now.Month() == 2 {
		if now.Year()%4 == 0 && (now.Year()%100 != 0 || now.Year()%400 == 0) {
			daysInMonth = 29
		} else {
			daysInMonth = 28
		}
	} else if now.Month() == 4 || now.Month() == 6 || now.Month() == 9 || now.Month() == 11 {
		daysInMonth = 30
	} else {
		daysInMonth = 31
	}
	
	// Calculate how many days have passed in the current month
	daysPassed := now.Sub(startOfMonth).Hours() / 24
	daysRemaining := daysInMonth - daysPassed
	
	// First, find out the earliest record in the database for this interface
	var earliestTimestamp string
	err := db.QueryRow(`
		SELECT MIN(timestamp) 
		FROM network_traffic 
		WHERE interface = ?
	`, interfaceName).Scan(&earliestTimestamp)
	
	if err != nil || earliestTimestamp == "" {
		return MonthEstimate{
			Interface:      interfaceName,
			EstimatedData:  0,
			HumanEstimated: "No data available",
		}, nil
	}
	
	// Parse the earliest timestamp
	earliestTime, err := time.Parse("2006-01-02 15:04:05", earliestTimestamp)
	if err != nil {
		return MonthEstimate{}, err
	}
	
	// Calculate the total time span we have data for (in hours)
	totalTimeSpan := now.Sub(earliestTime).Hours()
	
	// If we have less than 15 minutes of data, not enough for reliable estimate
	if totalTimeSpan < 0.25 {
		return MonthEstimate{
			Interface:      interfaceName,
			EstimatedData:  0,
			HumanEstimated: "Insufficient data (< 15 minutes)",
		}, nil
	}
	
	// Get total traffic over the entire time span
	var totalBytes sql.NullInt64
	err = db.QueryRow(`
		SELECT SUM(bytes_combined) 
		FROM network_traffic 
		WHERE interface = ?
	`, interfaceName).Scan(&totalBytes)
	
	if err != nil || !totalBytes.Valid || totalBytes.Int64 == 0 {
		return MonthEstimate{
			Interface:      interfaceName,
			EstimatedData:  0,
			HumanEstimated: "No traffic recorded",
		}, nil
	}
	
	// Calculate hourly rate based on all available data
	hourlyRate := float64(totalBytes.Int64) / totalTimeSpan
	
	// Get current month data if available
	var monthToDateBytes sql.NullInt64
	err = db.QueryRow(`
		SELECT SUM(bytes_combined) 
		FROM network_traffic 
		WHERE interface = ? AND timestamp >= ?
	`, interfaceName, startOfMonth.Format("2006-01-02 15:04:05")).Scan(&monthToDateBytes)
	
	var actualMonthBytes uint64
	if err == nil && monthToDateBytes.Valid {
		actualMonthBytes = uint64(monthToDateBytes.Int64)
	}
	
	// Format timespan for display
	var timespanText string
	if totalTimeSpan < 1.0 {
		// If less than 1 hour, show in minutes
		timespanText = fmt.Sprintf("%.0f min", totalTimeSpan*60)
	} else if totalTimeSpan < 24.0 {
		// If less than 1 day, show in hours
		timespanText = fmt.Sprintf("%.1f hours", totalTimeSpan)
	} else {
		// If more than 1 day, show in days
		timespanText = fmt.Sprintf("%.1f days", totalTimeSpan/24)
	}
	
	// Calculate monthly estimate
	var estimatedBytes uint64
	var estimateDescription string
	
	if daysPassed < 1.0 || actualMonthBytes == 0 {
		// Beginning of month or no month data yet - estimate entire month
		estimatedBytes = uint64(hourlyRate * 24.0 * daysInMonth)
		estimateDescription = fmt.Sprintf("(based on %s of data)", timespanText)
	} else {
		// Mid-month with some data - use actual data plus estimate for remaining days
		remainingEstimate := uint64(hourlyRate * 24.0 * daysRemaining)
		estimatedBytes = actualMonthBytes + remainingEstimate
		estimateDescription = fmt.Sprintf("(%s actual + estimate for remaining days)", humanReadableSize(actualMonthBytes))
	}
	
	// Add confidence level based on data span length
	if totalTimeSpan < 1.0 {
		estimateDescription += " [low confidence]"
	} else if totalTimeSpan < 24.0 {
		estimateDescription += " [medium confidence]"
	}
	
	return MonthEstimate{
		Interface:      interfaceName,
		EstimatedData:  estimatedBytes,
		HumanEstimated: humanReadableSize(estimatedBytes) + " " + estimateDescription,
	}, nil
}

func collectRoutine() {
	ticker := time.NewTicker(time.Duration(CollectInterval) * time.Second)
	defer ticker.Stop()

	cleanupTicker := time.NewTicker(24 * time.Hour)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ticker.C:
			collectTraffic()
		case <-cleanupTicker.C:
			cleanupOldData()
		}
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": Version})
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	hostname, _ := os.Hostname()
	uptime := formatUptime(time.Since(startTime))

	sysInfo := SystemInfo{
		Version:  Version,
		Uptime:   uptime,
		Hostname: hostname,
	}
	
	currentStats := make(map[string]TrafficStats)
	historyStats := make(map[string][]TrafficStats)
	monthEstimates := make([]MonthEstimate, 0)
	
	timeRanges := []string{"hour", "day", "week", "month", "year"}
	
	for _, iface := range interfaces {
		// Get current stats for all time ranges
		for _, tr := range timeRanges {
			stats, err := getTrafficStats(iface, tr)
			if err != nil {
				logger.Printf("Failed to get %s stats for %s: %v", tr, iface, err)
				continue
			}
			
			// Add to current stats for the interface with most recent time range (hour)
			if tr == "hour" {
				currentStats[iface] = stats
			}
			
			// Add to history stats
			if _, ok := historyStats[iface]; !ok {
				historyStats[iface] = make([]TrafficStats, 0)
			}
			historyStats[iface] = append(historyStats[iface], stats)
		}
		
		// Get month estimate
		estimate, err := getMonthEstimate(iface)
		if err != nil {
			logger.Printf("Failed to get month estimate for %s: %v", iface, err)
			continue
		}
		monthEstimates = append(monthEstimates, estimate)
	}
	
	response := AppResponse{
		SystemInfo:    sysInfo,
		CurrentStats:  currentStats,
		HistoryStats:  historyStats,
		MonthEstimates: monthEstimates,
	}
	
	json.NewEncoder(w).Encode(response)
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	// Simple HTML interface
	const htmlTemplate = `
	<!DOCTYPE html>
	<html>
	<head>
		<title>Network Traffic Monitor</title>
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<style>
			body {
				font-family: Arial, sans-serif;
				margin: 0;
				padding: 20px;
				line-height: 1.6;
			}
			.container {
				max-width: 1200px;
				margin: 0 auto;
			}
			h1, h2, h3 {
				color: #333;
			}
			table {
				width: 100%;
				border-collapse: collapse;
				margin: 20px 0;
			}
			th, td {
				padding: 12px 15px;
				border: 1px solid #ddd;
				text-align: left;
			}
			th {
				background-color: #f8f8f8;
			}
			tr:nth-child(even) {
				background-color: #f2f2f2;
			}
			.stats-container {
				display: flex;
				flex-wrap: wrap;
				gap: 20px;
			}
			.stats-box {
				flex: 1;
				min-width: 250px;
				padding: 15px;
				border: 1px solid #ddd;
				border-radius: 5px;
				background-color: #fff;
			}
			.info-bar {
				background-color: #f8f8f8;
				padding: 10px;
				border-radius: 5px;
				margin-bottom: 20px;
			}
			.refresh-btn {
				padding: 8px 16px;
				background-color: #4CAF50;
				color: white;
				border: none;
				border-radius: 4px;
				cursor: pointer;
			}
			.refresh-btn:hover {
				background-color: #45a049;
			}
		</style>
	</head>
	<body>
		<div class="container">
			<div class="info-bar">
				<h1>Network Traffic Monitor</h1>
				<p>Version: {{.Version}} | Uptime: {{.Uptime}} | Hostname: {{.Hostname}}</p>
				<button class="refresh-btn" onclick="window.location.reload()">Refresh Data</button>
			</div>

			{{range $iface, $stats := .CurrentStats}}
			<h2>Interface: {{$iface}}</h2>
			
			<div class="stats-container">
				<div class="stats-box">
					<h3>Latest Stats (Last Hour)</h3>
					<p>Received: {{$stats.HumanReceived}}</p>
					<p>Sent: {{$stats.HumanSent}}</p>
					<p>Combined: {{$stats.HumanCombined}}</p>
				</div>
				
				<div class="stats-box">
					<h3>Month Estimate</h3>
					{{range $.MonthEstimates}}
						{{if eq .Interface $iface}}
							<p>Estimated usage: {{.HumanEstimated}}</p>
						{{end}}
					{{end}}
				</div>
			</div>

			<h3>Historical Data</h3>
			<table>
				<thead>
					<tr>
						<th>Time Range</th>
						<th>Received</th>
						<th>Sent</th>
						<th>Combined</th>
					</tr>
				</thead>
				<tbody>
					{{range $histStats := index $.HistoryStats $iface}}
					<tr>
						<td>{{$histStats.TimeRange}}</td>
						<td>{{$histStats.HumanReceived}}</td>
						<td>{{$histStats.HumanSent}}</td>
						<td>{{$histStats.HumanCombined}}</td>
					</tr>
					{{end}}
				</tbody>
			</table>
			{{end}}
		</div>
	</body>
	</html>
	`

	tmpl, err := template.New("index").Parse(htmlTemplate)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get data for the template
	hostname, _ := os.Hostname()
	uptime := formatUptime(time.Since(startTime))
	
	currentStats := make(map[string]TrafficStats)
	historyStats := make(map[string][]TrafficStats)
	monthEstimates := make([]MonthEstimate, 0)
	
	timeRanges := []string{"hour", "day", "week", "month", "year"}
	
	for _, iface := range interfaces {
		// Get current stats for all time ranges
		for _, tr := range timeRanges {
			stats, err := getTrafficStats(iface, tr)
			if err != nil {
				logger.Printf("Failed to get %s stats for %s: %v", tr, iface, err)
				continue
			}
			
			// Add to current stats for the interface with most recent time range (hour)
			if tr == "hour" {
				currentStats[iface] = stats
			}
			
			// Add to history stats
			if _, ok := historyStats[iface]; !ok {
				historyStats[iface] = make([]TrafficStats, 0)
			}
			historyStats[iface] = append(historyStats[iface], stats)
		}
		
		// Get month estimate
		estimate, err := getMonthEstimate(iface)
		if err != nil {
			logger.Printf("Failed to get month estimate for %s: %v", iface, err)
			continue
		}
		monthEstimates = append(monthEstimates, estimate)
	}
	
	data := struct {
		Version        string
		Uptime         string
		Hostname       string
		CurrentStats   map[string]TrafficStats
		HistoryStats   map[string][]TrafficStats
		MonthEstimates []MonthEstimate
	}{
		Version:        Version,
		Uptime:         uptime, // This now uses the formatted uptime
		Hostname:       hostname,
		CurrentStats:   currentStats,
		HistoryStats:   historyStats,
		MonthEstimates: monthEstimates,
	}
	
	tmpl.Execute(w, data)
}

func startWebServer() {
	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/metrics", handleMetrics)
	http.HandleFunc("/health", handleHealth)
	
	logger.Println("Starting web server on :8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		logger.Fatalf("Failed to start web server: %v", err)
	}
}

func main() {
	startTime = time.Now()
	
	// Setup logger
	setupLogger()
	
	// Initialize the database
	initDB()
	defer db.Close()
	
	// Detect network interfaces
	detectInterfaces()
	
	// Start data collection in a goroutine
	go collectRoutine()
	
	// Start web server in a goroutine
	go startWebServer()
	
	// Wait for termination signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	
	logger.Println("Shutting down...")
}
