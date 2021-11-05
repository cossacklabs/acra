/*
Copyright 2020, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package logging

import (
	"bufio"
	"encoding/hex"
	"errors"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var auditLogKey, _ = hex.DecodeString("f1f6ff1960b3321d890eef6b26a64ecbf828b78a0b889349170ed2ca1a5812d1")

func TestJSONFormat(t *testing.T) {
	format := JSONFormatString
	verifier, channel, err := prepareTestInput(auditLogKey, format, nil)
	if err != nil {
		t.Fatal(err)
	}
	check(t, verifier, channel, format)
}

func TestCefFormat(t *testing.T) {
	format := CefFormatString
	verifier, source, err := prepareTestInput(auditLogKey, format, nil)
	if err != nil {
		t.Fatal(err)
	}
	check(t, verifier, source, format)
}

func TestPlaintextFormat(t *testing.T) {
	format := PlaintextFormatString
	verifier, channel, err := prepareTestInput(auditLogKey, format, nil)
	if err != nil {
		t.Fatal(err)
	}
	check(t, verifier, channel, format)
}

func TestUnknownFormat(t *testing.T) {
	format := "unknown"
	_, err := NewLogParser(format)
	if err != ErrUnexpectedFormat {
		t.Fatal("unexpected test behaviour")
	}
}

func TestIntegrityEnd(t *testing.T) {
	format := CefFormatString
	input := []string{
		`CEF:0|cossacklabs|acra-translator|0.85.0|100|Starting service acra-translator [pid\=4892]|1|unixTime=1583930295.386 integrity=cc3137f80f9ed2d172f9c4f2816e93d8624184973363780bf21ee271e5db1fb8 chain=new someAdditionField=12345`,
		`CEF:0|cossacklabs|acra-translator|0.85.0|100|Validating service configuration...|1|unixTime=1583930295.386 integrity=af251520c2a65b75bbb5aeeeb6bd981a12c401fc486d5d8ec3e86bcc66bcd2c5 someAdditionalField=67890`,
	}
	verifier, channel, err := prepareTestInput(auditLogKey, format, input)
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.VerifyIntegrityCheck(channel)
	var expectedErr hex.InvalidByteError
	if !errors.As(err, &expectedErr) {
		t.Fatal(err)
	}

	format = PlaintextFormatString
	input = []string{
		`time="2020-05-12T21:19:35+03:00" level=info msg="Test message with random information: bytSFuKJob" integrity=d49e55a26733dc0bddd3a47ef034059234550e799c48363b69f413ab2a4da07f chain=new`,
		`time="2020-05-12T21:19:35+03:00" level=info msg="Test message with random information: bMFWLOeqnM" integrity=e83c71bb3cb2fa909f78e0f141eb7fa0cb1dbe038cb355a94e6c403bfc1b9773`,
		`time="2020-05-12T21:19:35+03:00" level=info msg="Test message with random information: qquxyOrZnp" integrity=1ae68f7ca75948d19fea98ac577b3dd64d2661bd5d415cf17b4f8c571de10125`,
		`time="2020-05-12T21:19:35+03:00" level=info msg="Test message with random information: BsPVMvuzrh" integrity=a3d4335b587000b9e6753032a91722b8fec8d566d02f2321b2b3120a2f8c5cb5 someField=qwerty`,
	}
	verifier, channel, err = prepareTestInput(auditLogKey, format, input)
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.VerifyIntegrityCheck(channel)
	if !errors.As(err, &expectedErr) {
		t.Fatal(err)
	}
}

func TestMissingEndOfChain(t *testing.T) {
	testMissingEndOfChain(t, JSONFormatString)
	testMissingEndOfChain(t, CefFormatString)
	testMissingEndOfChain(t, PlaintextFormatString)
}
func testMissingEndOfChain(t *testing.T, format string) {
	var entries []string
	// generate 2 chains without valid EndOfChain message
	for i := 0; i < 2; i++ {
		chain, err := generateLogEntries(auditLogKey, format, true)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, chain...)
	}
	verifier, source, err := prepareTestInput(auditLogKey, format, entries)
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.VerifyIntegrityCheck(source)
	if !errors.As(err, &ErrMissingEndOfChain) {
		t.Fatal(err)
	}
}

func TestTruncationAttackPrevention(t *testing.T) {
	testTruncationAttackPrevention(t, JSONFormatString)
	testTruncationAttackPrevention(t, PlaintextFormatString)
	testTruncationAttackPrevention(t, CefFormatString)
}
func testTruncationAttackPrevention(t *testing.T, format string) {
	validChain, err := generateLogEntries(auditLogKey, format, false)
	if err != nil {
		t.Fatal(err)
	}
	// perform adversarial truncation of last entry
	validChain = validChain[0 : len(validChain)-1]

	// move EndOfChain marker to last but one entry, which is now last
	switch format {
	case JSONFormatString:
		validChain[len(validChain)-1] = strings.Replace(validChain[len(validChain)-1], "{", `{"chain":"end",`, 1)
	case PlaintextFormatString:
		validChain[len(validChain)-1] = strings.Replace(validChain[len(validChain)-1], "integrity", `chain=end integrity`, 1)
	case CefFormatString:
		validChain[len(validChain)-1] = strings.Replace(validChain[len(validChain)-1], "integrity", `chain=end integrity`, 1)
	default:
		t.Fatal("unexpected logging format has been specified")
	}
	verifier, source, err := prepareTestInput(auditLogKey, format, validChain)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := verifier.VerifyIntegrityCheck(source)
	// we expect that integrity will not match, since "check":"end" is cryptographically bounded to the log entry
	if !errors.As(err, &ErrIntegrityNotMatch) {
		t.Fatal(err)
	}
	// check additionally that we fail on last log entry (which is actually last but one after adversarial truncation)
	if !strings.EqualFold(entry.RawLogEntry, validChain[len(validChain)-1]) {
		t.Fatal(errors.New("failed verification on unexpected entry"))
	}
}

func check(t *testing.T, verifier *IntegrityCheckVerifier, source *LogEntrySource, format string) {
	logEntry, err := verifier.VerifyIntegrityCheck(source)
	if err != nil {
		if logEntry != nil {
			t.Fatal("Corrupted", "[", format, "]", logEntry.LineNumber, err)
		}
		t.Fatal(err)
	}
}
func generateLogEntries(key []byte, format string, skipChainFinalize bool) ([]string, error) {
	oldValue := logToFile
	logToFile = "unit_test_log.txt"
	defer func() {
		os.Remove(logToFile)
		logToFile = oldValue
	}()

	writer, finalizeLogWriter, err := NewWriter()
	if err != nil {
		return nil, err
	}
	hooks, err := NewHooks(key, format)
	if err != nil {
		return nil, err
	}
	formatter := CreateCryptoFormatter(format)
	formatter.SetServiceName("some-service-name")
	formatter.SetHooks(hooks)

	auditLogHandler, err := NewAuditLogHandler(formatter, writer)
	if err != nil {
		return nil, err
	}

	log.SetOutput(auditLogHandler)
	log.SetFormatter(auditLogHandler)

	log.WithField("version", utils.VERSION).Infof("Starting service %v [pid=%v]", "acra-translator", os.Getpid())
	log.Infof("Validating service configuration...")
	log.Infof("Configuring transport...")
	log.Infof("Selecting transport: use Secure Session transport wrapper")
	log.Infof("Setup ready. Start listening to connections. Current PID: %v", os.Getpid())
	log.Infof("Disabling future logs... Set -v -d to see logs")
	if !skipChainFinalize {
		auditLogHandler.FinalizeChain()
	}

	finalizeLogWriter()

	f, err := os.Open(logToFile)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(f)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, nil
}
func prepareTestInput(key []byte, format string, input []string) (*IntegrityCheckVerifier, *LogEntrySource, error) {
	var testInput []string
	if input == nil {
		// generate test input if it was not specified (2 times to test chaining)
		for i := 0; i < 2; i++ {
			logEntries, err := generateLogEntries(key, format, false)
			if err != nil {
				return nil, nil, err
			}
			testInput = append(testInput, logEntries...)
		}
	} else {
		testInput = input
	}
	parser, err := NewLogParser(format)
	if err != nil {
		return nil, nil, err
	}
	verifier, err := NewIntegrityCheckVerifier(key, parser)
	if err != nil {
		return nil, nil, err
	}
	channel := make(chan *LogEntryInfo)
	go func() {
		defer close(channel)
		var lineNumber = 0
		for _, line := range testInput {
			channel <- &LogEntryInfo{
				RawLogEntry: line,
				FileInfo:    nil,
				LineNumber:  lineNumber,
			}
			lineNumber++
		}
	}()
	return verifier, &LogEntrySource{
		Entries: channel,
		Error:   nil,
	}, nil
}

const NumberOfRotations = 10
const NumberOfLogChains = 10
const NumberOfRandomMessagesInChain = 10

func TestRotatedLogsWithLogRotate(t *testing.T) {
	if !isLogrotateInstalled() {
		t.Skip("logrotate not installed")
	}
	testRotatedLogs(t, path.Join(getBasePath(), "test_logrotate"), rotate)
}

func TestRotatedLogsManual(t *testing.T) {
	testRotatedLogs(t, path.Join(getBasePath(), "test_manual_rotate"), rotateManually)
}

func testRotatedLogs(t *testing.T, logDirectory string, rotate func(t *testing.T, logFileName string)) {
	format := PlaintextFormatString

	// prepare rotated logs
	logFileName := "log.txt"
	if _, err := os.Stat(logDirectory); err != nil {
		err := os.Mkdir(logDirectory, 0700)
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(logDirectory)
		generateRotatedLogs(logDirectory, logFileName, format, t, rotate)
	}

	// generate list of log files on the fly
	var absoluteFileNames []string
	fileInfos, err := ioutil.ReadDir(logDirectory)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(fileInfos) - 1; i >= 1; i-- {
		absoluteFileNames = append(absoluteFileNames, path.Join(logDirectory, fileInfos[i].Name()))
	}
	absoluteFileNames = append(absoluteFileNames, path.Join(logDirectory, logFileName))
	sort.Sort(asLogRotateTool(absoluteFileNames))

	// verify prepared logs
	logEntrySource := ReadLogEntries(absoluteFileNames, false, false)
	parser, err := NewLogParser(format)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewIntegrityCheckVerifier(auditLogKey, parser)
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.VerifyIntegrityCheck(logEntrySource)
	if err != nil {
		t.Fatal(err)
	}
}
func getBasePath() string {
	_, b, _, _ := runtime.Caller(0)
	return filepath.Dir(b)
}
func setLogFilePath(absFileName string) func() {
	oldValue := logToFile
	logToFile = absFileName
	result := func() {
		logToFile = oldValue
	}
	return result
}
func generateRotatedLogs(tempLogDir, logFileName, format string, t *testing.T, rotate func(t *testing.T, logFileName string)) {
	logFileName = path.Join(tempLogDir, logFileName)

	rand.Seed(time.Now().UnixNano())

	staticVarFinalize := setLogFilePath(logFileName)
	defer staticVarFinalize()

	writer, logWriterFinalize, err := NewWriter()
	if err != nil {
		t.Fatal(err)
	}
	hooks, err := NewHooks(auditLogKey, format)
	if err != nil {
		t.Fatal(err)
	}
	formatter := CreateCryptoFormatter(format)
	formatter.SetServiceName("some-service-name")
	formatter.SetHooks(hooks)

	auditLogHandler, err := NewAuditLogHandler(formatter, writer)
	if err != nil {
		t.Fatal(err)
	}

	log.SetOutput(auditLogHandler)
	log.SetFormatter(auditLogHandler)

	rotationsPerformed := 0
	for i := 0; i < NumberOfLogChains; i++ {
		// perform breaking current log chain by logs rotation
		pointOfRotation := rand.Intn(NumberOfRandomMessagesInChain)
		for j := 0; j < NumberOfRandomMessagesInChain; j++ {
			log.Infof("Test message with random information: " + randomize())
			if j == pointOfRotation {
				if rotationsPerformed < NumberOfRotations {
					rotate(t, logFileName)
					rotationsPerformed++
				}
			}
		}
		auditLogHandler.ResetChain(auditLogKey)
	}
	logWriterFinalize()
}
func randomize() string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, 10)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
func rotate(t *testing.T, logAbsPath string) {
	// generate logrotate config and state files on the fly
	logrotateConfig, err := ioutil.TempFile(getBasePath(), "logrotate.conf")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(logrotateConfig.Name())

	configContent := []string{
		logAbsPath + " {\n",
		"\thourly\n",
		"\trotate 24\n",
		"\tcopytruncate\n",
		"}\n",
	}
	for _, line := range configContent {
		_, err = logrotateConfig.WriteString(line)
		if err != nil {
			t.Fatal(err)
		}
	}
	logrotateConfig.Close()

	logrotateState, err := ioutil.TempFile(getBasePath(), "state")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(logrotateState.Name())
	_, err = logrotateState.WriteString("logrotate state -- version 2\n")
	if err != nil {
		t.Fatal(err)
	}
	logrotateState.Close()

	// perform rotation
	app := "logrotate"
	arg0 := logrotateConfig.Name()
	arg1 := "--force"
	arg2 := "--state"
	arg3 := logrotateState.Name()

	cmd := exec.Command(app, arg0, arg1, arg2, arg3)
	_, err = cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
}
func isLogrotateInstalled() bool {
	app := "logrotate"
	arg0 := "--help"
	cmd := exec.Command(app, arg0)
	_, err := cmd.Output()
	if err != nil {
		return false
	}
	return true
}
func rotateManually(t *testing.T, logAbsPath string) {
	logDirectory := filepath.Dir(logAbsPath)
	fileInfos, err := ioutil.ReadDir(logDirectory)
	if err != nil {
		t.Fatal(err)
	}

	currentLogs, err := ioutil.ReadFile(logAbsPath)
	if err != nil {
		t.Fatal(err)
	}

	// truncate current log file after reading its content
	err = os.Truncate(logAbsPath, 0)
	if err != nil {
		t.Fatal(err)
	}

	// handle previous rotations: log.txt.1 -> log.txt.2 -> log.txt.3 ... etc
	for i := len(fileInfos) - 1; i >= 1; i-- {
		err = os.Rename(logAbsPath+"."+strconv.Itoa(i), logAbsPath+"."+strconv.Itoa(i+1))
		if err != nil {
			t.Fatal(err)
		}
	}

	// handle current rotation: log.txt -> log.txt.1
	newFileName := logAbsPath + "." + strconv.Itoa(1)

	err = ioutil.WriteFile(newFileName, currentLogs, 0600)
	if err != nil {
		t.Fatal(err)
	}
}

// asLogRotateTool is a type defined for ordering of log files similar to well-known rotate tool
// (it is used currently only for testing purposes)
type asLogRotateTool []string

// Len is mandatory for implementation of sort interface
func (l asLogRotateTool) Len() int { return len(l) }

// Swap is mandatory for implementation of sort interface
func (l asLogRotateTool) Swap(i, j int) { l[i], l[j] = l[j], l[i] }

// Less is mandatory for implementation of sort interface
func (l asLogRotateTool) Less(i, j int) bool {
	// Use path names
	pathA := l[i]
	pathB := l[j]

	// Grab integer value of each filename by parsing the extension (without dot)
	a, err1 := strconv.ParseInt(path.Ext(pathA)[1:], 10, 64)
	b, err2 := strconv.ParseInt(path.Ext(pathB)[1:], 10, 64)

	// If any were not numbers sort by reverse-lexicographically
	if err1 != nil || err2 != nil {
		return pathA > pathB
	}

	// Which integer is greater?
	return a > b
}

func TestAuditLogChainConsistency(t *testing.T) {
	formats := []string{
		CefFormatString,
		PlaintextFormatString,
		JSONFormatString,
	}
	for _, format := range formats {
		for i := 0; i < 5; i++ {
			testAuditLogChainConsistency(t, format, multiplyReset)
			testAuditLogChainConsistency(t, format, multiplyFinalization)
			testAuditLogChainConsistency(t, format, concurrent)
		}
	}
}

func testAuditLogChainConsistency(t *testing.T, format string, entriesCombinator func(auditLogHandler *AuditLogHandler) error) {
	oldValue := logToFile
	logToFile = "unit_test_log.txt"
	defer func() {
		os.Remove(logToFile)
		logToFile = oldValue
	}()

	writer, finalizeLogWriter, err := NewWriter()
	if err != nil {
		t.Fatal(err)
	}
	defer finalizeLogWriter()

	hooks, err := NewHooks(auditLogKey, format)
	if err != nil {
		t.Fatal(err)
	}
	formatter := CreateCryptoFormatter(format)
	formatter.SetServiceName("some-service-name")
	formatter.SetHooks(hooks)
	auditLogHandler, err := NewAuditLogHandler(formatter, writer)
	if err != nil {
		t.Fatal(err)
	}

	log.SetOutput(auditLogHandler)
	log.SetFormatter(auditLogHandler)

	err = entriesCombinator(auditLogHandler)
	if err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(logToFile)
	if err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(f)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	verifier, source, err := prepareTestInput(auditLogKey, format, lines)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := verifier.VerifyIntegrityCheck(source)
	if err != nil {
		if entry != nil {
			println(entry.LineNumber)
		}
		t.Fatal(err)
	}
}
func multiplyFinalization(auditLogHandler *AuditLogHandler) error {
	// we can finalize chain multiply times without any problems because it doesn't reset crypto key
	// and consequently doesn't break verification
	for i := 0; i < 10; i++ {
		auditLogHandler.FinalizeChain()
	}
	return nil
}
func multiplyReset(auditLogHandler *AuditLogHandler) error {
	for i := 0; i < 10; i++ {
		auditLogHandler.ResetChain(auditLogKey)
	}
	auditLogHandler.FinalizeChain()
	return nil
}
func concurrent(auditLogHandler *AuditLogHandler) error {
	var synchronize sync.WaitGroup

	// just write "test message"
	synchronize.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			log.Infof("test message")
		}
	}(&synchronize)

	// just write "test message1"
	synchronize.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			log.Infof("test message1")
		}
	}(&synchronize)

	// just write "test message2"
	synchronize.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			log.Infof("test message2")
		}
	}(&synchronize)

	// just write "test message3"
	synchronize.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			log.Infof("test message3")
		}
	}(&synchronize)

	// reset chains
	synchronize.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			auditLogHandler.ResetChain(auditLogKey)
		}
	}(&synchronize)

	synchronize.Wait()

	auditLogHandler.FinalizeChain()
	return nil
}
