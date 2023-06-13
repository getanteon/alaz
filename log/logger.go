package log

import (
	"os"

	"github.com/rs/zerolog"
)

var (
	// Logger is the global logger.
	Logger zerolog.Logger
)

func init() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
}
