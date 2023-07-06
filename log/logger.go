package log

import (
	"os"
	"strconv"

	"github.com/rs/zerolog"
)

var (
	// Logger is the global logger.
	Logger zerolog.Logger
)

func init() {
	// Get the desired log level from environment variables
	levelStr := os.Getenv("LOG_LEVEL")

	// Set a default log level if the environment variable is not set
	defaultLevel := zerolog.InfoLevel

	// Parse the log level from the environment variable
	level, err := strconv.Atoi(levelStr)
	if err == nil {
		defaultLevel = zerolog.Level(level)
	}

	// Set the global log level for Zerolog
	zerolog.SetGlobalLevel(defaultLevel)

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
}
