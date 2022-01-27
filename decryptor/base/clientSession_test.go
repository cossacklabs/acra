package base


import (
	"context"
	"github.com/cossacklabs/acra/cmd/acra-server/common"
	"reflect"
	"testing"
)

func TestSetClientSessionToContext(t *testing.T) {
	session, err := common.NewClientSession(context.TODO(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if value := ClientSessionFromContext(ctx); value != nil {
		t.Fatal("Unexpected session value from empty context")
	}
	ctx = SetClientSessionToContext(ctx, session)
	value := ClientSessionFromContext(ctx)
	if !reflect.DeepEqual(value, session){
		t.Fatal("Returned incorrect session value")
	}
}