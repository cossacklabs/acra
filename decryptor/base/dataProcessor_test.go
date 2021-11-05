package base

import (
	"bytes"
	"errors"
	"testing"
)

type testProcessor struct {
	dataIndex    int
	returnData   []byte
	counter      *int
	err          error
	matchedIndex int
}

func (t *testProcessor) Process(data []byte, context *DataProcessorContext) ([]byte, error) {
	*t.counter++
	if *t.counter == t.dataIndex {
		return t.returnData, nil
	}
	return nil, t.err
}

func (t *testProcessor) MatchDataSignature(data []byte) bool {
	*t.counter++
	if *t.counter == t.matchedIndex {
		return true
	}
	return false
}

func TestChainProcessorError(t *testing.T) {
	testError := errors.New("test error")
	testData := []byte(`test data`)
	startData := []byte(`start data`)
	counter := 0
	// don't return any new data, always return errors
	processor1 := &testProcessor{returnData: testData, counter: &counter, err: testError}
	processor2 := &testProcessor{returnData: testData, counter: &counter, err: testError}
	chainProcessor := NewChainProcessorWrapper(processor1, processor2)

	output, err := chainProcessor.Process(startData, nil)
	if err != testError {
		t.Fatalf("Expect %s, took %s\n", testError, err)
	}
	if !bytes.Equal(output, startData) {
		t.Fatalf("Expect startData as data, took %v\nn", output)
	}
	if counter != 2 {
		t.Fatal("Called not all encryptors")
	}
}

func TestChainProcessorSuccess(t *testing.T) {
	testError := errors.New("test error")
	testData := []byte(`test data`)
	startData := []byte(`start data`)
	counter := 0
	// don't return any new data, always return errors
	processor1 := &testProcessor{returnData: testData, counter: &counter, err: testError}
	processor2 := &testProcessor{returnData: testData, counter: &counter, dataIndex: 2}
	chainProcessor := NewChainProcessorWrapper(processor1, processor2)

	output, err := chainProcessor.Process(startData, nil)
	if err != nil {
		t.Fatalf("Expect nil, took %s\n", err)
	}
	if !bytes.Equal(output, testData) {
		t.Fatalf("Expect testData as data, took %v\nn", output)
	}
	if counter != 2 {
		t.Fatal("Called not all encryptors")
	}
}

func TestChainProcessorMatchDataSignatureSuccess(t *testing.T) {
	startData := []byte(`start data`)
	counter := 0
	// don't return any new data, always return errors
	processor1 := &testProcessor{counter: &counter}
	processor2 := &testProcessor{matchedIndex: 2, counter: &counter}
	chainProcessor := NewChainProcessorWrapper(processor1, processor2)

	result := chainProcessor.MatchDataSignature(startData)
	if !result {
		t.Fatal("Expect result=true")
	}
	if counter != 2 {
		t.Fatal("Called not all encryptors")
	}
}

func TestChainProcessorMatchDataSignatureFailure(t *testing.T) {
	startData := []byte(`start data`)
	counter := 0
	// don't return any new data, always return errors
	processor1 := &testProcessor{counter: &counter}
	processor2 := &testProcessor{counter: &counter}
	chainProcessor := NewChainProcessorWrapper(processor1, processor2)

	result := chainProcessor.MatchDataSignature(startData)
	if result {
		t.Fatal("Expect result=false")
	}
	if counter != 2 {
		t.Fatal("Called not all encryptors")
	}
}
