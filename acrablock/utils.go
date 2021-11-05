package acrablock

import (
	"bytes"
	"context"
	"github.com/cossacklabs/acra/utils"
	"github.com/sirupsen/logrus"
)

// Processor interface used as callback for recognized AcraStructs and should return data instead AcraStruct
type Processor interface {
	OnAcraBlock(ctx context.Context, acraBlock AcraBlock) ([]byte, error)
}

// ProcessAcraBlocks find AcraBlocks in inBuffer, call processor on every recognized AcraStruct and replace it with result into outBuffer
// until end of data from inBuffer or any error result
// On error it returns inBuffer as is
func ProcessAcraBlocks(ctx context.Context, inBuffer []byte, outBuffer []byte, processor Processor) ([]byte, error) {
	logrus.Debugln("OnColumn: Try to decrypt AcraBlock")
	// inline mode
	if len(inBuffer) < AcraBlockMinSize {
		copy(outBuffer, inBuffer)
		return outBuffer, nil
	}
	inIndex := 0
	outIndex := 0
	for {
		// search AcraStruct's begin tags through all block of data and try to decrypt
		beginTagIndex := bytes.Index(inBuffer[inIndex:], tagBegin)
		if beginTagIndex == utils.NotFound {
			break
		}
		// convert to absolute index
		beginTagIndex += inIndex
		// write data before start of AcraStruct
		outBuffer = append(outBuffer[:outIndex], inBuffer[inIndex:beginTagIndex]...)
		outIndex += beginTagIndex - inIndex
		inIndex = beginTagIndex
		if len(inBuffer[inIndex:]) > AcraBlockMinSize {
			n, acraBlock, err := ExtractAcraBlockFromData(inBuffer[inIndex:])
			// we ignore errors related with invalid signature of AcraBlock, just go next and try to find next AcraBlock
			if err == nil {
				processedData, err := processor.OnAcraBlock(ctx, acraBlock)
				if err != nil {
					return inBuffer, err
				}
				outBuffer = append(outBuffer[:outIndex], processedData...)
				outIndex += len(processedData)
				inIndex += n
				continue
			}
		}
		// write current read byte to not process him in next iteration
		// write current read byte to not process him in next iteration
		outBuffer = append(outBuffer[:outIndex], inBuffer[inIndex])
		inIndex++
		outIndex++
		continue
	}
	// copy left bytes
	outBuffer = append(outBuffer[:outIndex], inBuffer[inIndex:]...)
	return outBuffer, nil
}
