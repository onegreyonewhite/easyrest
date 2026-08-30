package plugin

// CtxString returns ctx[key] as a string.
func CtxString(ctx map[string]any, key string) (string, bool) {
	if ctx == nil {
		return "", false
	}
	s, ok := ctx[key].(string)
	return s, ok
}

// AsInt coerces common numeric types to int.
func AsInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int8:
		return int(n), true
	case int16:
		return int(n), true
	case int32:
		return int(n), true
	case int64:
		return int(n), true
	case uint:
		return int(n), true
	case uint8:
		return int(n), true
	case uint16:
		return int(n), true
	case uint32:
		return int(n), true
	case uint64:
		if n > uint64(^uint(0)>>1) {
			return 0, false
		}
		return int(n), true
	case float32:
		return int(n), true
	case float64:
		return int(n), true
	default:
		return 0, false
	}
}

// IntFromCtx looks up ctx[key] and coerces it with AsInt.
func IntFromCtx(ctx map[string]any, key string) (int, bool) {
	if ctx == nil {
		return 0, false
	}
	return AsInt(ctx[key])
}
