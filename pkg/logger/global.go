package logger

import "go.uber.org/zap"

// Info logs an info message using the global logger
func Info(msg string, keysAndValues ...interface{}) {
	std.Sugar().Infow(msg, keysAndValues...)
}

// Debug logs a debug message using the global logger
func Debug(msg string, keysAndValues ...interface{}) {
	std.Sugar().Debugw(msg, keysAndValues...)
}

// Warn logs a warning message using the global logger
func Warn(msg string, keysAndValues ...interface{}) {
	std.Sugar().Warnw(msg, keysAndValues...)
}

// Error logs an error message using the global logger
func Error(msg string, keysAndValues ...interface{}) {
	std.Sugar().Errorw(msg, keysAndValues...)
}

// Fatal logs a fatal message and exits using the global logger
func Fatal(msg string, keysAndValues ...interface{}) {
	std.Sugar().Fatalw(msg, keysAndValues...)
}

// With creates a child logger with the specified fields
func With(keysAndValues ...interface{}) *zap.SugaredLogger {
	return std.Sugar().With(keysAndValues...)
}
