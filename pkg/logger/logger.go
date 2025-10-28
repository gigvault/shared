package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger wraps zap.Logger with convenience methods
type Logger struct {
	*zap.Logger
}

// Global logger instance
var std *Logger

func init() {
	// Initialize with development logger
	l, err := NewDevelopment()
	if err != nil {
		panic(err)
	}
	std = l
}

// SetGlobal sets the global logger instance
func SetGlobal(l *Logger) {
	std = l
}

// Global returns the global logger instance
func Global() *Logger {
	return std
}

// New creates a new logger with the specified level and format
func New(level, format string) (*Logger, error) {
	var config zap.Config

	if format == "json" {
		config = zap.NewProductionConfig()
	} else {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	// Set log level
	lvl, err := zapcore.ParseLevel(level)
	if err != nil {
		return nil, err
	}
	config.Level = zap.NewAtomicLevelAt(lvl)

	logger, err := config.Build()
	if err != nil {
		return nil, err
	}

	return &Logger{Logger: logger}, nil
}

// NewDevelopment creates a development logger
func NewDevelopment() (*Logger, error) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		return nil, err
	}
	return &Logger{Logger: logger}, nil
}

// NewProduction creates a production logger
func NewProduction() (*Logger, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, err
	}
	return &Logger{Logger: logger}, nil
}

// WithFields creates a new logger with the specified fields
func (l *Logger) WithFields(fields ...zap.Field) *Logger {
	return &Logger{Logger: l.Logger.With(fields...)}
}
