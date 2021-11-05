package logging

import (
	log "github.com/sirupsen/logrus"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const numberOfChains = 10
const numberOfLogEntriesInChain = 2000
const auditLogFilePath = "benchmark.txt"

func BenchmarkIO(b *testing.B) {
	pathToLogFile, err := filepath.Abs(auditLogFilePath)
	if err != nil {
		b.Fatal(err)
	}

	logFinalize := generateEntries(b, JSONFormatString, pathToLogFile, numberOfChains, numberOfLogEntriesInChain)
	defer func() {
		logFinalize()
		os.Remove(pathToLogFile)
	}()

	verifier := setupVerifier(b, JSONFormatString)

	// create b.N sources for common set of log entries, written in file (auditLogFilePath)
	sources := make([]*LogEntrySource, 0, b.N)

	// include IO operations into final benchmark results
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		source := setupLogEntrySource(b, pathToLogFile)
		sources = append(sources, source)
	}
	b.StopTimer()

	// let background goroutines to fill sources with some log entries
	time.Sleep(time.Millisecond * 50)

	// add verification time to benchmark result
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := verifier.VerifyIntegrityCheck(sources[i])
		if err != nil {
			b.Fatal(err)
		}
	}
	// include memory allocations into report
	b.ReportAllocs()
}

func BenchmarkCrypto(b *testing.B) {
	pathToLogFile, err := filepath.Abs(auditLogFilePath)
	if err != nil {
		b.Fatal(err)
	}

	logFinalize := generateEntries(b, JSONFormatString, pathToLogFile, numberOfChains, numberOfLogEntriesInChain)
	defer func() {
		logFinalize()
		os.Remove(pathToLogFile)
	}()

	verifier := setupVerifier(b, JSONFormatString)

	// create b.N sources for common set of log entries, written in file (auditLogFilePath)
	sources := make([]*LogEntrySource, 0, b.N)
	for i := 0; i < b.N; i++ {
		source := setupLogEntrySource(b, pathToLogFile)
		sources = append(sources, source)
	}

	// let background goroutines to fill sources with some log entries
	time.Sleep(time.Millisecond * 50)

	// start estimation from here (only crypto operations)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := verifier.VerifyIntegrityCheck(sources[i])
		if err != nil {
			b.Fatal(err)
		}
	}
	// include memory allocations into report
	b.ReportAllocs()
}

func generateEntries(b *testing.B, format, path string, numberOfChains, numberOfLinesInChain int) func() {
	oldValue := logToFile
	logToFile = path
	defer func() {
		logToFile = oldValue
	}()

	auditLogHandler, logFinalize := setupAuditLogHandler(b, format)
	for i := 0; i < numberOfChains; i++ {
		for i := 0; i < numberOfLinesInChain; i++ {
			log.Infof("Test message " + strconv.Itoa(i))
		}
		auditLogHandler.FinalizeChain()
	}

	return logFinalize
}

func setupAuditLogHandler(b *testing.B, format string) (*AuditLogHandler, func()) {
	writer, logFinalize, err := NewWriter()
	if err != nil {
		b.Fatal(err)
	}
	hooks, err := NewHooks(auditLogKey, format)
	if err != nil {
		b.Fatal(err)
	}
	formatter := CreateCryptoFormatter(format)
	formatter.SetServiceName("crypto-benchmark")
	formatter.SetHooks(hooks)
	auditLogHandler, err := NewAuditLogHandler(formatter, writer)
	if err != nil {
		b.Fatal(err)
	}
	log.SetOutput(auditLogHandler)
	log.SetFormatter(auditLogHandler)
	return auditLogHandler, logFinalize
}

func setupVerifier(b *testing.B, format string) *IntegrityCheckVerifier {
	parser, err := NewLogParser(format)
	if err != nil {
		b.Fatal(err)
	}
	verifier, err := NewIntegrityCheckVerifier(auditLogKey, parser)
	if err != nil {
		b.Fatal(err)
	}
	return verifier
}

func setupLogEntrySource(b *testing.B, path string) *LogEntrySource {
	return ReadLogEntries([]string{path}, false, false)
}
