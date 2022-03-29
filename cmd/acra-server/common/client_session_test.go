package common

import (
	"context"
	"reflect"
	"testing"
)

func TestClientSession_Data(t *testing.T) {
	session, err := NewClientSession(context.TODO(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	type testcase struct {
		key  string
		data interface{}
	}
	testcases := []testcase{
		{`binary key`, []byte(`binary data`)},
		{`string key`, `string value`},
		{`int key`, 123},
		{`struct key`, testcase{`123`, `123`}},
	}
	overwriteValue := `some value that will overwrite existing value`
	for _, tcase := range testcases {
		if session.HasData(tcase.key) {
			t.Fatal("session should not have value of not used key")
		}
		value, ok := session.GetData(tcase.key)
		if ok {
			t.Fatal("session should not have value of not used key")
		}
		if value != nil {
			t.Fatal("session should return nil for not existing keys")
		}
		session.SetData(tcase.key, tcase.data)
		if !session.HasData(tcase.key) {
			t.Fatal("session hasn't value of existing key")
		}
		value, ok = session.GetData(tcase.key)
		if !ok {
			t.Fatal("session hasn't value of of existing key")
		}
		if !reflect.DeepEqual(tcase.data, value) {
			t.Fatal("session returned another value")
		}

		// overwrite value and check that it successfully overwritten
		session.SetData(tcase.key, overwriteValue)
		if !session.HasData(tcase.key) {
			t.Fatal("session hasn't value of existing key")
		}
		value, ok = session.GetData(tcase.key)
		if !ok {
			t.Fatal("session hasn't value of of existing key")
		}
		if !reflect.DeepEqual(overwriteValue, value) {
			t.Fatal("session returned another value")
		}

		session.DeleteData(tcase.key)
		if session.HasData(tcase.key) {
			t.Fatal("session should not have value of not used key")
		}
		value, ok = session.GetData(tcase.key)
		if ok {
			t.Fatal("session should not have value of not used key")
		}
		if value != nil {
			t.Fatal("session should return nil for not existing keys")
		}
	}
}
