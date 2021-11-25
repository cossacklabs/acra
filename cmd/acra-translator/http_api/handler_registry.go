package http_api

import (
	"context"
	"github.com/cossacklabs/acra/cmd/acra-translator/common"
	"github.com/gin-gonic/gin"
	"sync"
)

// HTTPServerSubscriber interface declares callbacks raised by HTTP server
type HTTPServerSubscriber interface {
	OnHTTPServerInit(ctx context.Context, engine *gin.Engine, data *common.TranslatorData, httpService *HTTPService)
}

// subscribers global list of callbacks for HTTP server instance
var subscribers = make([]HTTPServerSubscriber, 0, 8)
var lock = sync.Mutex{}

// AddHTTPServerSubscriber register callback to HTTP server
func AddHTTPServerSubscriber(subscriber HTTPServerSubscriber) {
	lock.Lock()
	subscribers = append(subscribers, subscriber)
	lock.Unlock()
}

// OnHTTPServerInit call all registered callbacks on HTTP server initialization
func OnHTTPServerInit(ctx context.Context, engine *gin.Engine, data *common.TranslatorData, httpService *HTTPService) {
	lock.Lock()
	defer lock.Unlock()
	for _, subscriber := range subscribers {
		subscriber.OnHTTPServerInit(ctx, engine, data, httpService)
	}
}
