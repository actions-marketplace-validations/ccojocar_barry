package logging

import (
	"log/slog"
	"os"
	"sync"
)

var (
	logger *slog.Logger
	once   sync.Once
)

// Get returns the singleton structured logger.
func Get() *slog.Logger {
	once.Do(func() {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
	})
	return logger
}
