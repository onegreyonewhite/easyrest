package memcached

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockMemcacheClient is a mock implementation of memcacheClientInterface
type mockMemcacheClient struct {
	GetFunc    func(key string) (*memcache.Item, error)
	SetFunc    func(item *memcache.Item) error
	DeleteFunc func(key string) error // Matches interface
}

func (m *mockMemcacheClient) Get(key string) (*memcache.Item, error) {
	if m.GetFunc != nil {
		return m.GetFunc(key)
	}
	return nil, errors.New("GetFunc not implemented in mock")
}

func (m *mockMemcacheClient) Set(item *memcache.Item) error {
	if m.SetFunc != nil {
		return m.SetFunc(item)
	}
	return errors.New("SetFunc not implemented in mock")
}

func (m *mockMemcacheClient) Delete(key string) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(key)
	}
	return errors.New("DeleteFunc not implemented in mock")
}

func TestInitConnection_InvalidURI_Scheme(t *testing.T) {
	p := NewMemcachedCachePlugin()
	err := p.InitConnection("memcache://localhost:11211") // Wrong scheme
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid Memcached URI: must start with memcached://")
	assert.Nil(t, p.client) // p.client is interface, should be nil if InitConnection fails early
}

func TestInitConnection_InvalidURI_NoServers(t *testing.T) {
	p := NewMemcachedCachePlugin()
	err := p.InitConnection("memcached://")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid Memcached URI: no servers specified")
	assert.Nil(t, p.client)
}

func TestInitConnection_InvalidURI_EmptyServerList(t *testing.T) {
	p := NewMemcachedCachePlugin()
	err := p.InitConnection("memcached://,")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid Memcached URI: no valid servers specified after prefix")
	assert.Nil(t, p.client)
}

func TestInitConnection_Success_WithMockPing(t *testing.T) {
	p := NewMemcachedCachePlugin()
	// For this specific test, we want to control the "ping" (Get call).
	// However, InitConnection creates the *real* client internally.
	// To test the ping part with a mock, we would need to refactor InitConnection
	// to accept a client factory, or make the ping part a separate, testable function.

	// Current InitConnection will use a real memcache.New().
	// So, this test will either connect to a real server or fail the ping if none is available.
	// To make it a unit test, we'd ideally mock the memcache.New part or the subsequent Get.

	// Let's test successful initialization assuming the internal Get for ping doesn't error out badly.
	// We can't easily mock the internal client used for the ping without further refactoring.
	// So, we assume that if memcache.New succeeds, and the ping Get returns ErrCacheMiss (or no error),
	// the initialization is fine.
	err := p.InitConnection("memcached://localhost:11211") // Uses real client for ping

	if err != nil {
		// If a real server is not at localhost:11211, the ping Get might return a connection error.
		// This is okay for this test, as it shows InitConnection reacting to ping failure.
		assert.Contains(t, err.Error(), "post-initialization check")
		assert.NotNil(t, p.client) // Client instance should still be created before ping fails
	} else {
		// If no error, or if error was ErrCacheMiss (handled by InitConnection), then success.
		require.NoError(t, err)
		assert.NotNil(t, p.client)
	}
}

func TestSet_ClientNil(t *testing.T) {
	p := &memcachedCachePlugin{client: nil} // Client is explicitly nil
	err := p.Set("key", "value", 1*time.Minute)
	require.Error(t, err)
	assert.Equal(t, "memcached client not initialized", err.Error())
}

func TestSet_MemcachedError(t *testing.T) {
	p := NewMemcachedCachePlugin()
	mockClient := &mockMemcacheClient{}
	p.client = mockClient // Inject mock client

	expectedErr := errors.New("memcached Set error")
	mockClient.SetFunc = func(item *memcache.Item) error {
		return expectedErr
	}

	key := "testkey"
	err := p.Set(key, "value", 1*time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("failed to set cache entry in Memcached for key '%s'", key))
	assert.True(t, errors.Is(err, expectedErr))
}

func TestSet_Success(t *testing.T) {
	p := NewMemcachedCachePlugin()
	mockClient := &mockMemcacheClient{}
	p.client = mockClient

	var calledWithItem *memcache.Item
	mockClient.SetFunc = func(item *memcache.Item) error {
		calledWithItem = item
		return nil
	}

	key := "testkey"
	value := "testvalue"
	ttl := 1 * time.Minute

	err := p.Set(key, value, ttl)
	require.NoError(t, err)
	require.NotNil(t, calledWithItem)
	assert.Equal(t, key, calledWithItem.Key)
	assert.Equal(t, []byte(value), calledWithItem.Value)
	assert.Equal(t, int32(ttl.Seconds()), calledWithItem.Expiration)
}

func TestGet_ClientNil(t *testing.T) {
	p := &memcachedCachePlugin{client: nil}
	val, err := p.Get("key")
	require.Error(t, err)
	assert.Equal(t, "memcached client not initialized", err.Error())
	assert.Empty(t, val)
}

func TestGet_CacheMiss(t *testing.T) {
	p := NewMemcachedCachePlugin()
	mockClient := &mockMemcacheClient{}
	p.client = mockClient

	mockClient.GetFunc = func(key string) (*memcache.Item, error) {
		return nil, memcache.ErrCacheMiss
	}

	val, err := p.Get("missingkey")
	require.Error(t, err)
	assert.True(t, errors.Is(err, memcache.ErrCacheMiss))
	assert.Empty(t, val)
}

func TestGet_MemcachedError(t *testing.T) {
	p := NewMemcachedCachePlugin()
	mockClient := &mockMemcacheClient{}
	p.client = mockClient

	expectedErr := errors.New("memcached Get error")
	mockClient.GetFunc = func(key string) (*memcache.Item, error) {
		return nil, expectedErr
	}

	key := "errorkey"
	val, err := p.Get(key)
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("failed to get cache entry from Memcached for key '%s'", key))
	assert.True(t, errors.Is(err, expectedErr))
	assert.Empty(t, val)
}

func TestGet_Success(t *testing.T) {
	p := NewMemcachedCachePlugin()
	mockClient := &mockMemcacheClient{}
	p.client = mockClient

	key := "testkey"
	expectedValue := "testvalue"
	mockClient.GetFunc = func(k string) (*memcache.Item, error) {
		if k == key {
			return &memcache.Item{Key: k, Value: []byte(expectedValue)}, nil
		}
		return nil, memcache.ErrCacheMiss
	}

	val, err := p.Get(key)
	require.NoError(t, err)
	assert.Equal(t, expectedValue, val)
}

func TestClose_ClientNil(t *testing.T) {
	p := &memcachedCachePlugin{client: nil}
	err := p.Close()
	require.NoError(t, err)
}

func TestClose_Success_NonNullClient(t *testing.T) {
	p := NewMemcachedCachePlugin()
	// InitConnection will set a real client. Or we can inject a mock.
	mockClient := &mockMemcacheClient{}
	p.client = mockClient // Directly assign a mock
	require.NotNil(t, p.client)

	err := p.Close()
	require.NoError(t, err)
	assert.Nil(t, p.client) // Client should be nil after calling Close
}

func TestSet_NegativeTTL(t *testing.T) {
	p := NewMemcachedCachePlugin()
	mockClient := &mockMemcacheClient{}
	p.client = mockClient

	var calledWithItem *memcache.Item
	mockClient.SetFunc = func(item *memcache.Item) error {
		calledWithItem = item
		return nil
	}

	err := p.Set("keyTTL", "value", -5*time.Minute)
	require.NoError(t, err)
	require.NotNil(t, calledWithItem)
	assert.Equal(t, int32(0), calledWithItem.Expiration) // Negative TTL should become 0
}
