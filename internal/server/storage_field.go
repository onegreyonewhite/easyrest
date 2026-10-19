package server

// storageValueKind is how a REST field is stored.
// None means the field is ordinary data.
type storageValueKind int

const (
	storageValueNone storageValueKind = iota
	storageValueBinary
	storageValueBinaryList
	storageValueBase64
	storageValueBase64List
)

func storageValueKindOf(raw any) storageValueKind {
	prop, ok := raw.(map[string]any)
	if !ok {
		return storageValueNone
	}
	typ, _ := prop["type"].(string)
	if typ == "array" {
		items, _ := prop["items"].(map[string]any)
		return storageListKind(items)
	}
	if typ != "string" {
		return storageValueNone
	}
	return storageScalarKind(prop)
}

func storageScalarKind(prop map[string]any) storageValueKind {
	format, _ := prop["format"].(string)
	switch format {
	case "binary":
		return storageValueBinary
	case "base64":
		return storageValueBase64
	default:
		return storageValueNone
	}
}

func storageListKind(items map[string]any) storageValueKind {
	switch storageScalarKind(items) {
	case storageValueBinary:
		return storageValueBinaryList
	case storageValueBase64:
		return storageValueBase64List
	default:
		return storageValueNone
	}
}

func storageFieldsOf(props map[string]any) map[string]storageValueKind {
	out := map[string]storageValueKind{}
	for name, raw := range props {
		kind := storageValueKindOf(raw)
		if kind == storageValueNone {
			continue
		}
		out[name] = kind
	}
	return out
}

func storageKindList(kind storageValueKind) bool {
	return kind == storageValueBinaryList || kind == storageValueBase64List
}
