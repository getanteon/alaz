package kafka

import (
	"time"
)

type Timestamp struct {
	*time.Time
}

func (t Timestamp) decode(pd packetDecoder) error {
	millis, err := pd.getInt64()
	if err != nil {
		return err
	}

	// negative timestamps are invalid, in these cases we should return
	// a zero time
	timestamp := time.Time{}
	if millis >= 0 {
		timestamp = time.Unix(millis/1000, (millis%1000)*int64(time.Millisecond))
	}

	*t.Time = timestamp
	return nil
}
