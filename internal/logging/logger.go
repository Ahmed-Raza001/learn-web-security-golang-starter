package logging

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Logger struct {
	mutex sync.Mutex
	file  *os.File
	now   func() time.Time
}

var sensitiveFields = map[string]struct{}{
	"sessionId":          {},
	"resetToken":         {},
	"resetLink":          {},
	"secret":             {},
	"adminNotes":         {},
	"storagePath":        {},
	"email":              {},
	"shippingName":       {},
	"shippingAddress":    {},
	"shippingCity":       {},
	"shippingRegion":     {},
	"shippingPostalCode": {},
	"originalName":       {},
}

func Open(filePath string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}

	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open application log: %w", err)
	}

	return &Logger{file: file, now: time.Now}, nil
}

func (logger *Logger) Close() error {
	return logger.file.Close()
}

func (logger *Logger) Event(eventName string, fields map[string]any) error {
	record := map[string]any{
		"timestamp": logger.now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"event":     eventName,
	}

	for key, value := range fields {
		record[key] = sanitizeField(key, value)
	}

	logger.mutex.Lock()
	defer logger.mutex.Unlock()

	if err := json.NewEncoder(logger.file).Encode(record); err != nil {
		return fmt.Errorf("encoding log record: %w", err)
	}

	return nil
}

func sanitizeField(key string, value any) any {
	normalizedKey := strings.ToLower(key)
	normalizedKey = strings.NewReplacer(
		"_", "",
		"-", "",
		" ", "",
	).Replace(normalizedKey)

	sensitiveKeywords := []string{
		"password",
		"passwd",
		"token",
		"secret",
		"apikey",
		"authorization",
		"cookie",
		"sessionid",
		"resetlink",
	}

	for sensitiveKey := range sensitiveFields {
		normalizedSensitiveKey := strings.ToLower(sensitiveKey)
		normalizedSensitiveKey = strings.NewReplacer(
			"_", "",
			"-", "",
			" ", "",
		).Replace(normalizedSensitiveKey)

		if normalizedKey == normalizedSensitiveKey {
			return "[REDACTED]"
		}
	}

	for _, keyword := range sensitiveKeywords {
		if strings.Contains(normalizedKey, keyword) {
			return "[REDACTED]"
		}
	}

	switch v := value.(type) {
	case map[string]any:
		sanitized := make(map[string]any, len(v))

		for nestedKey, nestedValue := range v {
			sanitized[nestedKey] = sanitizeField(nestedKey, nestedValue)
		}

		return sanitized

	case []any:
		sanitized := make([]any, len(v))

		for i, item := range v {
			if nestedMap, ok := item.(map[string]any); ok {
				sanitized[i] = sanitizeFieldMap(nestedMap)
			} else {
				sanitized[i] = item
			}
		}

		return sanitized

	default:
		return value
	}
}

func sanitizeFieldMap(fields map[string]any) map[string]any {
	sanitized := make(map[string]any, len(fields))

	for key, value := range fields {
		sanitized[key] = sanitizeField(key, value)
	}

	return sanitized
}
