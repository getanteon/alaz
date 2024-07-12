package kafka

import (
	"errors"

	"github.com/ddosify/alaz/log"

	"time"
)

type AbortedTransaction struct {
	// ProducerID contains the producer id associated with the aborted transaction.
	ProducerID int64
	// FirstOffset contains the first offset in the aborted transaction.
	FirstOffset int64
}

func (t *AbortedTransaction) decode(pd packetDecoder) (err error) {
	if t.ProducerID, err = pd.getInt64(); err != nil {
		return err
	}

	if t.FirstOffset, err = pd.getInt64(); err != nil {
		return err
	}

	return nil
}

type FetchResponseBlock struct {
	// Err contains the error code, or 0 if there was no fetch error.
	Err KError
	// HighWatermarkOffset contains the current high water mark.
	HighWaterMarkOffset int64
	// LastStableOffset contains the last stable offset (or LSO) of the
	// partition. This is the last offset such that the state of all
	// transactional records prior to this offset have been decided (ABORTED or
	// COMMITTED)
	LastStableOffset       int64
	LastRecordsBatchOffset *int64
	// LogStartOffset contains the current log start offset.
	LogStartOffset int64
	// AbortedTransactions contains the aborted transactions.
	AbortedTransactions []*AbortedTransaction
	// PreferredReadReplica contains the preferred read replica for the
	// consumer to use on its next fetch request
	PreferredReadReplica int32
	// RecordsSet contains the record data.
	RecordsSet []*Records

	Partial bool
	Records *Records // deprecated: use FetchResponseBlock.RecordsSet
}

func (b *FetchResponseBlock) decode(pd packetDecoder, version int16) (err error) {
	tmp, err := pd.getInt16()
	if err != nil {
		return err
	}
	b.Err = KError(tmp)

	b.HighWaterMarkOffset, err = pd.getInt64()
	if err != nil {
		return err
	}

	if version >= 4 {
		b.LastStableOffset, err = pd.getInt64()
		if err != nil {
			return err
		}

		if version >= 5 {
			b.LogStartOffset, err = pd.getInt64()
			if err != nil {
				return err
			}
		}

		numTransact, err := pd.getArrayLength()
		if err != nil {
			return err
		}

		if numTransact >= 0 {
			b.AbortedTransactions = make([]*AbortedTransaction, numTransact)
		}

		for i := 0; i < numTransact; i++ {
			transact := new(AbortedTransaction)
			if err = transact.decode(pd); err != nil {
				return err
			}
			b.AbortedTransactions[i] = transact
		}
	}

	if version >= 11 {
		b.PreferredReadReplica, err = pd.getInt32()
		if err != nil {
			return err
		}
	} else {
		b.PreferredReadReplica = -1
	}

	recordsSize, err := pd.getInt32()
	if err != nil {
		return err
	}

	recordsDecoder, err := pd.getSubset(int(recordsSize))
	if err != nil {
		return err
	}

	b.RecordsSet = []*Records{}

	for recordsDecoder.remaining() > 0 {
		records := &Records{}
		if err := records.decode(recordsDecoder); err != nil {
			// If we have at least one decoded records, this is not an error
			if errors.Is(err, ErrInsufficientData) {
				if len(b.RecordsSet) == 0 {
					b.Partial = true
				}
				break
			}
			return err
		}

		b.LastRecordsBatchOffset, err = records.recordsOffset()
		if err != nil {
			return err
		}

		partial, err := records.isPartial()
		if err != nil {
			return err
		}

		n, err := records.numRecords()
		if err != nil {
			return err
		}

		if n > 0 || (partial && len(b.RecordsSet) == 0) {
			b.RecordsSet = append(b.RecordsSet, records)

			if b.Records == nil {
				b.Records = records
			}
		}

		overflow, err := records.isOverflow()
		if err != nil {
			return err
		}

		if partial || overflow {
			break
		}
	}

	return nil
}

type FetchResponse struct {
	// Version defines the protocol version to use for encode and decode
	Version int16
	// ThrottleTime contains the duration in milliseconds for which the request
	// was throttled due to a quota violation, or zero if the request did not
	// violate any quota.
	ThrottleTime time.Duration
	// ErrorCode contains the top level response error code.
	ErrorCode int16
	// SessionID contains the fetch session ID, or 0 if this is not part of a fetch session.
	SessionID int32
	// Blocks contains the response topics.
	Blocks map[string]map[int32]*FetchResponseBlock

	LogAppendTime bool
	Timestamp     time.Time
}

func (r *FetchResponse) decode(pd packetDecoder, version int16) (err error) {
	r.Version = version

	if r.Version >= 1 {
		throttle, err := pd.getInt32()
		if err != nil {
			return err
		}
		r.ThrottleTime = time.Duration(throttle) * time.Millisecond
	}

	if r.Version >= 7 {
		r.ErrorCode, err = pd.getInt16()
		if err != nil {
			return err
		}
		r.SessionID, err = pd.getInt32()
		if err != nil {
			return err
		}
	}

	numTopics, err := pd.getArrayLength()
	if err != nil {
		return err
	}

	log.Logger.Warn().Msgf("sarama-numTopics: %d", numTopics)

	r.Blocks = make(map[string]map[int32]*FetchResponseBlock, numTopics)
	for i := 0; i < numTopics; i++ {
		name, err := pd.getString()
		if err != nil {
			return err
		}

		numBlocks, err := pd.getArrayLength()
		if err != nil {
			return err
		}

		r.Blocks[name] = make(map[int32]*FetchResponseBlock, numBlocks)

		for j := 0; j < numBlocks; j++ {
			id, err := pd.getInt32()
			if err != nil {
				return err
			}

			block := new(FetchResponseBlock)
			err = block.decode(pd, version)
			if err != nil {
				return err
			}
			r.Blocks[name][id] = block
		}
	}

	return nil
}

func (r *FetchResponse) key() int16 {
	return 1
}

func (r *FetchResponse) version() int16 {
	return r.Version
}

func (r *FetchResponse) headerVersion() int16 {
	return 0
}

func (r *FetchResponse) isValidVersion() bool {
	return r.Version >= 0 && r.Version <= 11
}

func (r *FetchResponse) requiredVersion() KafkaVersion {
	switch r.Version {
	case 11:
		return V2_3_0_0
	case 9, 10:
		return V2_1_0_0
	case 8:
		return V2_0_0_0
	case 7:
		return V1_1_0_0
	case 6:
		return V1_0_0_0
	case 4, 5:
		return V0_11_0_0
	case 3:
		return V0_10_1_0
	case 2:
		return V0_10_0_0
	case 1:
		return V0_9_0_0
	case 0:
		return V0_8_2_0
	default:
		return V2_3_0_0
	}
}
