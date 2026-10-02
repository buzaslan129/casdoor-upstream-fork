//go:build integration

package object

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/casbin/casbin/v2/model"
	"github.com/xorm-io/xorm"
	_ "github.com/lib/pq"
)

const (
	cockroachTestIdentity = "casdoor-safe-adapter-crdb"
	cockroachTestDatabase = "casdoor_safe_adapter_test"
	cockroachTestTable    = "casbin_api_rule_integration"
)

func TestSafeAdapterCockroachRepeatedWritesPreserveCustomTable(t *testing.T) {
	dsn := os.Getenv("CASDOOR_COCKROACH_TEST_DSN")
	if os.Getenv("CASDOOR_COCKROACH_TEST_ALLOW_DISPOSABLE") != cockroachTestIdentity || dsn == "" {
		t.Skip("requires explicit opt-in and DSN for the owned disposable CockroachDB test container")
	}

	parsedDSN, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse disposable test DSN: %v", err)
	}
	if parsedDSN.Hostname() != cockroachTestIdentity || parsedDSN.Path != "/"+cockroachTestDatabase || parsedDSN.Query().Get("sslmode") != "disable" {
		t.Fatalf("refusing DSN outside the owned disposable test identity/database")
	}

	probe, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open CockroachDB identity probe: %v", err)
	}
	defer probe.Close()

	var version, database string
	if err := probe.QueryRow("SELECT version(), current_database()").Scan(&version, &database); err != nil {
		t.Fatalf("read disposable CockroachDB identity: %v", err)
	}
	if !strings.Contains(version, "v26.2.7") || database != cockroachTestDatabase {
		t.Fatalf("unexpected disposable database identity: version=%q database=%q", version, database)
	}
	var tableCount int
	if err := probe.QueryRow("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'").Scan(&tableCount); err != nil {
		t.Fatalf("check disposable database is empty: %v", err)
	}
	if tableCount != 0 {
		t.Fatalf("refusing nonempty disposable database: found %d public tables", tableCount)
	}

	engine, err := xorm.NewEngine("postgres", dsn)
	if err != nil {
		t.Fatalf("open CockroachDB Xorm engine: %v", err)
	}
	tableCreated := false
	t.Cleanup(func() {
		if tableCreated {
			if _, err := engine.Exec("DROP TABLE " + cockroachTestTable); err != nil {
				t.Errorf("drop owned integration table: %v", err)
			}
		}
		if err := engine.Close(); err != nil {
			t.Errorf("close CockroachDB Xorm engine: %v", err)
		}
	})

	_, err = engine.Exec(`CREATE TABLE ` + cockroachTestTable + ` (
		id INT8 NOT NULL DEFAULT unique_rowid(),
		ptype STRING NOT NULL DEFAULT '',
		v0 STRING NOT NULL DEFAULT '',
		v1 STRING NOT NULL DEFAULT '',
		v2 STRING NOT NULL DEFAULT '',
		v3 STRING NOT NULL DEFAULT '',
		v4 STRING NOT NULL DEFAULT '',
		v5 STRING NOT NULL DEFAULT '',
		PRIMARY KEY (id)
	)`)
	if err != nil {
		t.Fatalf("create expanded STRING-compatible custom table: %v", err)
	}
	tableCreated = true
	if _, err := engine.Exec("CREATE INDEX casbin_api_rule_integration_marker_idx ON " + cockroachTestTable + " (ptype)"); err != nil {
		t.Fatalf("create marker index: %v", err)
	}

	safeAdapter := &SafeAdapter{engine: engine, tableName: cockroachTestTable}

	firstPolicy := newCockroachPolicyModel(t, [][]string{{"built-in", "*", "*", "*", "*", "*"}})
	if err := safeAdapter.SavePolicy(firstPolicy); err != nil {
		t.Fatalf("first SavePolicy(): %v", err)
	}
	secondPolicy := newCockroachPolicyModel(t, [][]string{
		{"app", "*", "GET", "/api/get-account", "*", "*"},
		{"*", "*", "POST", "/api/login", "*", "*"},
	})
	if err := safeAdapter.SavePolicy(secondPolicy); err != nil {
		t.Fatalf("repeated SavePolicy(): %v", err)
	}
	assertCockroachPolicyRows(t, safeAdapter, [][]string{
		{"app", "*", "GET", "/api/get-account", "*", "*"},
		{"*", "*", "POST", "/api/login", "*", "*"},
	})

	if err := safeAdapter.UpdatePolicy("p", "p",
		[]string{"app", "*", "GET", "/api/get-account", "*", "*"},
		[]string{"app", "*", "GET", "/api/get-user", "*", "*"}); err != nil {
		t.Fatalf("UpdatePolicy(): %v", err)
	}
	assertCockroachPolicyRows(t, safeAdapter, [][]string{
		{"app", "*", "GET", "/api/get-user", "*", "*"},
		{"*", "*", "POST", "/api/login", "*", "*"},
	})

	if err := safeAdapter.RemovePolicy("p", "p", []string{"*", "*", "POST", "/api/login", "*", "*"}); err != nil {
		t.Fatalf("RemovePolicy(): %v", err)
	}
	assertCockroachPolicyRows(t, safeAdapter, [][]string{
		{"app", "*", "GET", "/api/get-user", "*", "*"},
	})

	indexes, err := probe.Query("SHOW INDEXES FROM " + cockroachTestTable)
	if err != nil {
		t.Fatalf("read custom table indexes: %v", err)
	}
	defer indexes.Close()
	indexColumns, err := indexes.Columns()
	if err != nil {
		t.Fatalf("read custom table index columns: %v", err)
	}
	indexNameColumn := -1
	for i, column := range indexColumns {
		if column == "index_name" {
			indexNameColumn = i
			break
		}
	}
	if indexNameColumn == -1 {
		t.Fatalf("SHOW INDEXES result has no index_name column: %v", indexColumns)
	}
	markerIndexFound := false
	for indexes.Next() {
		values := make([]any, len(indexColumns))
		scanArgs := make([]any, len(values))
		for i := range values {
			scanArgs[i] = &values[i]
		}
		if err := indexes.Scan(scanArgs...); err != nil {
			t.Fatalf("scan custom table index: %v", err)
		}
		if fmt.Sprint(values[indexNameColumn]) == "casbin_api_rule_integration_marker_idx" {
			markerIndexFound = true
		}
	}
	if err := indexes.Err(); err != nil {
		t.Fatalf("iterate custom table indexes: %v", err)
	}
	if !markerIndexFound {
		t.Fatal("SavePolicy() removed the custom table marker index")
	}
	columns, err := probe.Query("SHOW COLUMNS FROM " + cockroachTestTable)
	if err != nil {
		t.Fatalf("read expanded STRING-compatible schema: %v", err)
	}
	defer columns.Close()
	columnNames, err := columns.Columns()
	if err != nil {
		t.Fatalf("read custom table column metadata: %v", err)
	}
	columnIndex, typeIndex := -1, -1
	for i, name := range columnNames {
		switch name {
		case "column_name":
			columnIndex = i
		case "data_type":
			typeIndex = i
		}
	}
	if columnIndex == -1 || typeIndex == -1 {
		t.Fatalf("SHOW COLUMNS result lacks column_name or data_type: %v", columnNames)
	}
	policyColumns := map[string]bool{"ptype": false, "v0": false, "v1": false, "v2": false, "v3": false, "v4": false, "v5": false}
	for columns.Next() {
		values := make([]any, len(columnNames))
		scanArgs := make([]any, len(values))
		for i := range values {
			scanArgs[i] = &values[i]
		}
		if err := columns.Scan(scanArgs...); err != nil {
			t.Fatalf("scan custom table column metadata: %v", err)
		}
		name := fmt.Sprint(values[columnIndex])
		if _, isPolicyColumn := policyColumns[name]; !isPolicyColumn {
			continue
		}
		dataType := strings.ToUpper(fmt.Sprint(values[typeIndex]))
		if dataType != "STRING" && dataType != "VARCHAR" && dataType != "CHARACTER VARYING" && dataType != "TEXT" {
			t.Errorf("policy column %s has type %q, want a STRING-compatible type", name, dataType)
		}
		policyColumns[name] = true
	}
	if err := columns.Err(); err != nil {
		t.Fatalf("iterate custom table columns: %v", err)
	}
	for name, found := range policyColumns {
		if !found {
			t.Errorf("custom table is missing STRING-compatible policy column %s", name)
		}
	}
}

func newCockroachPolicyModel(t *testing.T, policies [][]string) model.Model {
	t.Helper()
	m, err := model.NewModelFromString(`[request_definition]
r = subOwner, subName, method, urlPath, objOwner, objName

[policy_definition]
p = subOwner, subName, method, urlPath, objOwner, objName

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.subOwner == p.subOwner && r.subName == p.subName && r.method == p.method && r.urlPath == p.urlPath && r.objOwner == p.objOwner && r.objName == p.objName`)
	if err != nil {
		t.Fatalf("parse policy model: %v", err)
	}
	for _, policy := range policies {
		m["p"]["p"].Policy = append(m["p"]["p"].Policy, policy)
	}
	return m
}

func assertCockroachPolicyRows(t *testing.T, adapter *SafeAdapter, want [][]string) {
	t.Helper()
	rules, err := adapter.GetRules()
	if err != nil {
		t.Fatalf("GetRules(): %v", err)
	}
	if len(rules) != len(want) {
		t.Fatalf("GetRules() returned %d rows, want %d: %#v", len(rules), len(want), rules)
	}
	for _, policy := range want {
		found := false
		for _, rule := range rules {
			if rule.Ptype == "p" && rule.V0 == policy[0] && rule.V1 == policy[1] && rule.V2 == policy[2] && rule.V3 == policy[3] && rule.V4 == policy[4] && rule.V5 == policy[5] {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("policy %v missing from CockroachDB rows %#v", policy, rules)
		}
	}
}
