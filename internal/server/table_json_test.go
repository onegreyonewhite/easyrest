package server

import (
	"strings"
	"testing"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func TestProcessSelectParamJSON(t *testing.T) {
	t.Parallel()

	fields, group, err := processSelectParam("id,json_data->>blood_type,json_data->phones", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantFields := []string{
		"id",
		`json_data->>'blood_type' AS "blood_type"`,
		`json_data->'phones' AS "phones"`,
	}
	wantGroup := []string{
		"id",
		`json_data->>'blood_type'`,
		`json_data->'phones'`,
	}
	if strings.Join(fields, "|") != strings.Join(wantFields, "|") {
		t.Fatalf("fields %#v", fields)
	}
	if strings.Join(group, "|") != strings.Join(wantGroup, "|") {
		t.Fatalf("group %#v", group)
	}

	fields, group, err = processSelectParam("id,json_data->phones->0->>number", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 2 || fields[1] != `json_data->'phones'->0->>'number' AS "number"` {
		t.Fatalf("nested %#v", fields)
	}
	if group[1] != `json_data->'phones'->0->>'number'` {
		t.Fatalf("nested group %#v", group)
	}

	fields, group, err = processSelectParam("id,primary_language:languages->0", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fields[1] != "languages->0 AS primary_language" {
		t.Fatalf("alias %#v", fields)
	}
	if group[1] != "languages->0" {
		t.Fatalf("alias group %#v", group)
	}

	fields, group, err = processSelectParam("json_data->>BloodType,amount.sum()", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fields[0] != `json_data->>'BloodType' AS "BloodType"` || !strings.Contains(fields[1], "SUM(amount)") {
		t.Fatalf("mixed case and aggregate %#v", fields)
	}
	if len(group) != 1 || group[0] != `json_data->>'BloodType'` {
		t.Fatalf("aggregate group %#v", group)
	}

	fields, _, err = processSelectParam("json_data ->> blood_type", nil, nil)
	if err != nil || len(fields) != 1 || fields[0] != `json_data->>'blood_type' AS "blood_type"` {
		t.Fatalf("spaces: %v %#v", err, fields)
	}

	if _, _, err := processSelectParam("languages->0", nil, nil); err == nil || !strings.Contains(err.Error(), "array index") {
		t.Fatalf("index alias: %v", err)
	}
	if _, _, err := processSelectParam("json_data->>blood;drop", nil, nil); err == nil {
		t.Fatal("expected injection to fail")
	}
	if _, _, err := processSelectParam("json_data->>a->b", nil, nil); err == nil {
		t.Fatal("expected ->> in the middle to fail")
	}
}

func TestParseWhereClauseJSON(t *testing.T) {
	t.Parallel()

	where, err := ParseWhereClause(map[string][]string{
		"where.eq.json_data->>blood_type": {"A-"},
		"where.gt.json_data->age":         {"20"},
		"where.not.eq.json_data->>city":   {"Berlin"},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	eq, _ := where[`json_data->>'blood_type'`].(map[string]any)
	if eq["="] != "A-" {
		t.Fatalf("text filter %#v", where)
	}
	gt, _ := where[`json_data->'age'`].(map[string]any)
	if gt[">"] != "20" {
		t.Fatalf("json filter %#v", where)
	}
	notEq, _ := where[`NOT json_data->>'city'`].(map[string]any)
	if notEq["="] != "Berlin" {
		t.Fatalf("not filter %#v", where)
	}

	if _, err := ParseWhereClause(map[string][]string{
		"where.gt.json_data->age": {"A-"},
	}, nil, nil); err == nil || !strings.Contains(err.Error(), "valid json") {
		t.Fatalf("non-json value: %v", err)
	}
	if _, err := ParseWhereClause(map[string][]string{
		"where.like.json_data->age": {"20"},
	}, nil, nil); err == nil || !strings.Contains(err.Error(), "->>") {
		t.Fatalf("like on ->: %v", err)
	}
	if _, err := ParseWhereClause(map[string][]string{
		"where.eq.json_data->>blood;drop": {"A-"},
	}, nil, nil); err == nil {
		t.Fatal("expected injection to fail")
	}
	if _, err := ParseWhereClause(map[string][]string{
		"where.like.json_data->>blood_type": {"A%"},
	}, nil, nil); err != nil {
		t.Fatal(err)
	}

	_, err = ParseWhereClause(map[string][]string{
		"where.gt.json_data->ok": {"true"},
	}, nil, map[string]any{easyrest.CtxDBType: easyrest.DialectSQLite})
	if err == nil || !strings.Contains(err.Error(), "sqlite") {
		t.Fatalf("sqlite bool ordering: %v", err)
	}
	if _, err := ParseWhereClause(map[string][]string{
		"where.gt.json_data->age": {"20"},
	}, nil, map[string]any{easyrest.CtxDBType: easyrest.DialectSQLite}); err != nil {
		t.Fatal(err)
	}
}
