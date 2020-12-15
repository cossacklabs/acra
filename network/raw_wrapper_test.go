package network

import "testing"

func TestRawConnectionWrapper(t *testing.T) {
	var testClientID = []byte("client")
	testWrapper(&RawConnectionWrapper{}, &RawConnectionWrapper{ClientID: testClientID}, testClientID, wrapperCommunicationIterations, t)
}

func BenchmarkRawConnectionWrapper(t *testing.B) {
	var testClientID = []byte("client")
	testWrapper(&RawConnectionWrapper{}, &RawConnectionWrapper{ClientID: testClientID}, testClientID, t.N, t)
}
