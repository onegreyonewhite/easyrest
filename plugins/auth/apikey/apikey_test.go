package apikey

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyAuthPlugin_Init(t *testing.T) {
	t.Run("Successful initialization with default header_name", func(t *testing.T) {
		plugin := &APIKeyAuthPlugin{}
		settings := map[string]any{
			"keys": []string{"key1", "key2"},
		}
		schema, err := plugin.Init(settings)
		require.NoError(t, err)
		require.NotNil(t, schema)
		assert.Equal(t, "apiKey", schema["type"])
		assert.Equal(t, "X-API-Key", schema["name"]) // Default
		assert.Equal(t, "header", schema["in"])
		assert.Equal(t, "X-API-Key", plugin.headerName)
		expectedKeys := map[string]struct{}{"key1": {}, "key2": {}}
		assert.Equal(t, expectedKeys, plugin.validKeys)
	})

	t.Run("Successful initialization with custom header_name", func(t *testing.T) {
		plugin := &APIKeyAuthPlugin{}
		settings := map[string]any{
			"keys":        []string{"key1"},
			"header_name": "My-Custom-API-Header",
		}
		schema, err := plugin.Init(settings)
		require.NoError(t, err)
		require.NotNil(t, schema)
		assert.Equal(t, "apiKey", schema["type"])
		assert.Equal(t, "My-Custom-API-Header", schema["name"])
		assert.Equal(t, "header", schema["in"])
		assert.Equal(t, "My-Custom-API-Header", plugin.headerName)
	})

	t.Run("Successful initialization with keys as []any of strings", func(t *testing.T) {
		plugin := &APIKeyAuthPlugin{}
		settings := map[string]any{
			"keys": []any{"key1", "key2"},
		}
		schema, err := plugin.Init(settings)
		require.NoError(t, err)
		require.NotNil(t, schema)
		expectedKeys := map[string]struct{}{"key1": {}, "key2": {}}
		assert.Equal(t, expectedKeys, plugin.validKeys)
	})

	t.Run("Initialization with non-string element in keys []any", func(t *testing.T) {
		plugin := &APIKeyAuthPlugin{}
		settings := map[string]any{
			"keys": []any{"key1", 123},
		}
		_, err := plugin.Init(settings)
		require.Error(t, err)
		assert.EqualError(t, err, "keys array contains non-string element at index 1")
	})

	t.Run("Initialization with missing keys setting", func(t *testing.T) {
		plugin := &APIKeyAuthPlugin{}
		settings := map[string]any{}
		_, err := plugin.Init(settings)
		require.Error(t, err)
		assert.EqualError(t, err, "keys setting is required and must be a []string")
	})

	t.Run("Initialization with invalid keys type", func(t *testing.T) {
		plugin := &APIKeyAuthPlugin{}
		settings := map[string]any{
			"keys": "not-a-slice",
		}
		_, err := plugin.Init(settings)
		require.Error(t, err)
		assert.EqualError(t, err, "keys setting must be a []string or []any (with string elements)")
	})

	t.Run("Initialization with empty keys list", func(t *testing.T) {
		plugin := &APIKeyAuthPlugin{}
		settings := map[string]any{
			"keys": []string{},
		}
		_, err := plugin.Init(settings)
		require.Error(t, err)
		assert.EqualError(t, err, "keys list cannot be empty")
	})

	t.Run("Initialization with empty string in keys list", func(t *testing.T) {
		plugin := &APIKeyAuthPlugin{}
		settings := map[string]any{
			"keys": []string{"key1", ""},
		}
		_, err := plugin.Init(settings)
		require.Error(t, err)
		assert.EqualError(t, err, "API key cannot be empty or just whitespace")
	})

	t.Run("Initialization with whitespace string in keys list", func(t *testing.T) {
		plugin := &APIKeyAuthPlugin{}
		settings := map[string]any{
			"keys": []string{"key1", "   "},
		}
		_, err := plugin.Init(settings)
		require.Error(t, err)
		assert.EqualError(t, err, "API key cannot be empty or just whitespace")
	})

	t.Run("Initialization with empty custom header_name (uses default)", func(t *testing.T) {
		plugin := &APIKeyAuthPlugin{}
		settings := map[string]any{
			"keys":        []string{"key1"},
			"header_name": "   ", // Whitespace, should use default
		}
		schema, err := plugin.Init(settings)
		require.NoError(t, err)
		assert.Equal(t, "X-API-Key", schema["name"])
		assert.Equal(t, "X-API-Key", plugin.headerName)
	})
}

func TestAPIKeyAuthPlugin_Authenticate(t *testing.T) {
	plugin := &APIKeyAuthPlugin{}
	validKeys := []string{"secret-key-1", "secret-key-2"}
	customHeader := "X-My-Token"

	_, err := plugin.Init(map[string]any{"keys": validKeys, "header_name": customHeader})
	require.NoError(t, err)

	t.Run("Successful authentication with custom header", func(t *testing.T) {
		headers := map[string]string{
			customHeader: "secret-key-1",
		}
		claims, err := plugin.Authenticate(headers, "GET", "/path", "query=param")
		require.NoError(t, err)
		require.NotNil(t, claims)
		assert.Equal(t, "secret-key-1", claims["sub"])
		assert.Equal(t, "read write", claims["scope"])
	})

	t.Run("Successful authentication - case-insensitive header name match", func(t *testing.T) {
		headers := map[string]string{
			"x-my-token": "secret-key-2", // Lowercase version of customHeader
		}
		claims, err := plugin.Authenticate(headers, "GET", "/path", "query=param")
		require.NoError(t, err)
		require.NotNil(t, claims)
		assert.Equal(t, "secret-key-2", claims["sub"])
	})

	t.Run("Missing headers map", func(t *testing.T) {
		_, err := plugin.Authenticate(nil, "GET", "/path", "query=param")
		require.Error(t, err)
		assert.EqualError(t, err, "missing headers")
	})

	t.Run("Empty headers map", func(t *testing.T) {
		_, err := plugin.Authenticate(map[string]string{"X-API-Key": ""}, "GET", "/path", "query=param")
		require.Error(t, err)
		assert.EqualError(t, err, fmt.Sprintf("missing or empty API key in header %s", customHeader))
	})

	t.Run("Missing API key header", func(t *testing.T) {
		headers := map[string]string{
			"AnotherHeader": "value",
		}
		_, err := plugin.Authenticate(headers, "GET", "/path", "query=param")
		require.Error(t, err)
		assert.EqualError(t, err, fmt.Sprintf("missing or empty API key in header %s", customHeader))
	})

	t.Run("Empty API key in header", func(t *testing.T) {
		headers := map[string]string{
			customHeader: "",
		}
		_, err := plugin.Authenticate(headers, "GET", "/path", "query=param")
		require.Error(t, err)
		assert.EqualError(t, err, fmt.Sprintf("missing or empty API key in header %s", customHeader))
	})

	t.Run("API key in header is only whitespace", func(t *testing.T) {
		headers := map[string]string{
			customHeader: "   ",
		}
		_, err := plugin.Authenticate(headers, "GET", "/path", "query=param")
		require.Error(t, err)
		assert.EqualError(t, err, fmt.Sprintf("missing or empty API key in header %s", customHeader))
	})

	t.Run("Invalid API key", func(t *testing.T) {
		headers := map[string]string{
			customHeader: "invalid-key",
		}
		_, err := plugin.Authenticate(headers, "GET", "/path", "query=param")
		require.Error(t, err)
		assert.EqualError(t, err, "invalid API key")
	})

	t.Run("Default header X-API-Key", func(t *testing.T) {
		pluginDefault := &APIKeyAuthPlugin{}
		_, initErr := pluginDefault.Init(map[string]any{"keys": []string{"defaultKey"}})
		require.NoError(t, initErr)

		headers := map[string]string{
			"X-API-Key": "defaultKey",
		}
		claims, err := pluginDefault.Authenticate(headers, "GET", "/path", "query")
		require.NoError(t, err)
		assert.Equal(t, "defaultKey", claims["sub"])

		headersLower := map[string]string{
			"x-api-key": "defaultKey",
		}
		claimsLower, errLower := pluginDefault.Authenticate(headersLower, "GET", "/path", "query")
		require.NoError(t, errLower)
		assert.Equal(t, "defaultKey", claimsLower["sub"])

		_, errMissing := pluginDefault.Authenticate(map[string]string{"foo": "bar"}, "GET", "/path", "query")
		require.Error(t, errMissing)
		assert.EqualError(t, errMissing, "missing or empty API key in header X-API-Key")
	})
}
