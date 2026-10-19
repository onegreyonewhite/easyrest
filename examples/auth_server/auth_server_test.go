package auth_server_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/goccy/go-json"
)

func TestDiscovery(t *testing.T) {
	client, base := testClient(t)
	issuer := base + "/restapi/v1"
	doc := getJSON(t, client, issuer+"/.well-known/openid-configuration")
	if doc.StatusCode != http.StatusOK {
		t.Fatalf("discovery status %d body %s", doc.StatusCode, doc.Body)
	}
	if _, ok := doc.JSON["results"]; ok {
		t.Fatalf("discovery wrapped %#v", doc.JSON)
	}
	if doc.JSON["issuer"] != issuer {
		t.Fatalf("issuer %#v", doc.JSON["issuer"])
	}
	want := map[string]string{
		"authorization_endpoint": issuer + "/authorize/start",
		"token_endpoint":         issuer + "/token",
		"userinfo_endpoint":      issuer + "/userinfo/claims",
		"jwks_uri":               issuer + "/jwks/public",
	}
	for key, value := range want {
		if doc.JSON[key] != value {
			t.Fatalf("%s %#v", key, doc.JSON[key])
		}
	}
	if !jsonEqual(doc.JSON["token_endpoint_auth_methods_supported"], []any{"client_secret_basic", "none"}) {
		t.Fatalf("auth methods %#v", doc.JSON["token_endpoint_auth_methods_supported"])
	}
	if !jsonEqual(doc.JSON["code_challenge_methods_supported"], []any{"S256"}) {
		t.Fatalf("pkce %#v", doc.JSON["code_challenge_methods_supported"])
	}
	if !jsonEqual(doc.JSON["id_token_signing_alg_values_supported"], []any{"RS256"}) {
		t.Fatalf("algs %#v", doc.JSON["id_token_signing_alg_values_supported"])
	}
	slashed := getJSON(t, client, issuer+"/.well-known/openid-configuration/")
	if slashed.StatusCode != http.StatusNotFound {
		t.Fatalf("slashed discovery status %d", slashed.StatusCode)
	}

	keys := getJSON(t, client, issuer+"/jwks/public")
	if keys.StatusCode != http.StatusOK {
		t.Fatalf("jwks status %d body %s", keys.StatusCode, keys.Body)
	}
	list, ok := keys.JSON["keys"].([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("keys %#v", keys.JSON["keys"])
	}
	jwk, ok := list[0].(map[string]any)
	if !ok || jwk["kty"] != "RSA" || jwk["alg"] != "RS256" || jwk["n"] == "" || jwk["e"] == "" {
		t.Fatalf("jwk %#v", list[0])
	}
}

func TestLogin(t *testing.T) {
	client, base := testClient(t)
	next := base + "/restapi/v1/authorize/start?client_id=spa&response_type=code"

	bad := postForm(t, client, base+"/restapi/v1/login/", url.Values{
		"email":    {"alice@example.com"},
		"password": {"wrong"},
		"next":     {next},
	})
	if bad.StatusCode != http.StatusUnauthorized || bad.Header.Get("Set-Cookie") != "" {
		t.Fatalf("wrong password status %d cookie %q body %s", bad.StatusCode, bad.Header.Get("Set-Cookie"), bad.Body)
	}
	if bad.JSON["error"] != "invalid email or password" {
		t.Fatalf("wrong password body %#v", bad.JSON)
	}

	disabled := postForm(t, client, base+"/restapi/v1/login/", url.Values{
		"email":    {"bob@example.com"},
		"password": {"bob"},
		"next":     {next},
	})
	if disabled.StatusCode != http.StatusUnauthorized || disabled.Header.Get("Set-Cookie") != "" || disabled.JSON["error"] != "invalid email or password" {
		t.Fatalf("bob status %d cookie %q body %#v", disabled.StatusCode, disabled.Header.Get("Set-Cookie"), disabled.JSON)
	}

	ok := postForm(t, client, base+"/restapi/v1/login/", url.Values{
		"email":    {"alice@example.com"},
		"password": {"alice"},
		"next":     {next},
	})
	if ok.StatusCode != http.StatusFound || ok.Header.Get("Location") != next {
		t.Fatalf("alice status %d location %q", ok.StatusCode, ok.Header.Get("Location"))
	}
	session := ok.Cookies["session"]
	if session == nil || !session.HttpOnly || !session.Secure || session.Value == "" {
		t.Fatalf("session cookie %#v", session)
	}

	other := postForm(t, client, base+"/restapi/v1/login/", url.Values{
		"email":    {"alice@example.com"},
		"password": {"alice"},
		"next":     {"https://evil.example/restapi/v1/authorize/start"},
	})
	if other.StatusCode != http.StatusBadRequest || other.Header.Get("Set-Cookie") != "" {
		t.Fatalf("foreign next status %d cookie %q", other.StatusCode, other.Header.Get("Set-Cookie"))
	}
	home := postForm(t, client, base+"/restapi/v1/login/", url.Values{
		"email":    {"alice@example.com"},
		"password": {"alice"},
		"next":     {""},
	})
	if home.StatusCode != http.StatusFound || home.Header.Get("Location") != "https://localhost:8443/" || home.Cookies["session"] == nil {
		t.Fatalf("empty next status %d location %q", home.StatusCode, home.Header.Get("Location"))
	}

	for i := 0; i < 9; i++ {
		resp := postForm(t, client, base+"/restapi/v1/login/", url.Values{
			"email":    {"bob@example.com"},
			"password": {"wrong"},
			"next":     {next},
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("bob attempt %d status %d", i+2, resp.StatusCode)
		}
	}
	blocked := postForm(t, client, base+"/restapi/v1/login/", url.Values{
		"email":    {"bob@example.com"},
		"password": {"wrong"},
		"next":     {next},
	})
	if blocked.StatusCode != http.StatusTooManyRequests || blocked.Header.Get("Retry-After") == "" {
		t.Fatalf("lockout status %d retry %q", blocked.StatusCode, blocked.Header.Get("Retry-After"))
	}
	still := postForm(t, client, base+"/restapi/v1/login/", url.Values{
		"email":    {"bob@example.com"},
		"password": {"bob"},
		"next":     {next},
	})
	if still.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("correct password during lockout status %d", still.StatusCode)
	}
}

func TestHealth(t *testing.T) {
	client, base := testClient(t)
	resp, err := client.Get(base + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "OK" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
}

type formResult struct {
	StatusCode int
	Header     http.Header
	Cookies    map[string]*http.Cookie
	JSON       map[string]any
	Body       string
}

func getJSON(t *testing.T, client *http.Client, endpoint string) formResult {
	t.Helper()
	resp, err := client.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	out := formResult{StatusCode: resp.StatusCode, Header: resp.Header, Body: string(raw)}
	if len(raw) > 0 && raw[0] == '{' {
		if err := json.Unmarshal(raw, &out.JSON); err != nil {
			t.Fatalf("json %q: %v", raw, err)
		}
	}
	return out
}

func jsonEqual(got any, want []any) bool {
	list, ok := got.([]any)
	if !ok || len(list) != len(want) {
		return false
	}
	for i := range want {
		if list[i] != want[i] {
			return false
		}
	}
	return true
}

func postForm(t *testing.T, client *http.Client, endpoint string, values url.Values) formResult {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	out := formResult{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Cookies:    map[string]*http.Cookie{},
		Body:       string(raw),
	}
	for _, cookie := range resp.Cookies() {
		out.Cookies[cookie.Name] = cookie
	}
	if len(raw) > 0 && raw[0] == '{' {
		if err := json.Unmarshal(raw, &out.JSON); err != nil {
			t.Fatalf("json %q: %v", raw, err)
		}
	}
	return out
}

func testClient(t *testing.T) (*http.Client, string) {
	t.Helper()
	base := os.Getenv("AUTH_SERVER_URL")
	if base == "" {
		t.Skip("AUTH_SERVER_URL is not set")
	}
	if base != "https://localhost:8443" {
		t.Fatalf("AUTH_SERVER_URL = %q, want https://localhost:8443", base)
	}
	caPath := os.Getenv("AUTH_SERVER_CA")
	if caPath == "" {
		t.Fatal("AUTH_SERVER_CA is not set")
	}
	pem, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatalf("AUTH_SERVER_CA %s has no certificate", caPath)
	}
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}
	return client, strings.TrimRight(base, "/")
}

func TestAuthorizeCode(t *testing.T) {
	client, base := testClient(t)
	issuer := base + "/restapi/v1"
	verifier, challenge := pkcePair(t)
	query := spaQuery(challenge, "state-1", "nonce-1", "openid profile email")
	authURL := issuer + "/authorize/start?" + query.Encode()

	anon := getRaw(t, client, authURL, "")
	if anon.StatusCode != http.StatusFound || !strings.Contains(anon.Header.Get("Location"), "/media/static/login.html") {
		t.Fatalf("anonymous authorize %d %s", anon.StatusCode, anon.Header.Get("Location"))
	}

	session := loginSession(t, client, issuer, "alice@example.com", "alice", authURL)
	consent := getRaw(t, client, authURL, session)
	if consent.StatusCode != http.StatusFound || !strings.Contains(consent.Header.Get("Location"), "/media/static/consent.html") {
		t.Fatalf("consent %d %s", consent.StatusCode, consent.Header.Get("Location"))
	}
	allowed := postRaw(t, client, issuer+"/consent/decide", url.Values{"decision": {"allow"}, "next": {authURL}}, session, "", "")
	if allowed.StatusCode != http.StatusFound || allowed.Header.Get("Location") != authURL {
		t.Fatalf("allow %d %s", allowed.StatusCode, allowed.Header.Get("Location"))
	}
	granted := getRaw(t, client, authURL, session)
	code := callbackCode(t, granted, "state-1")

	token := postRaw(t, client, issuer+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"spa"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:9876/callback"},
		"code_verifier": {verifier},
	}, "", "", "")
	if token.StatusCode != http.StatusOK {
		t.Fatalf("token %d %s", token.StatusCode, token.Body)
	}
	if !strings.Contains(token.Header.Get("Cache-Control"), "no-store") {
		t.Fatalf("cache %q", token.Header.Get("Cache-Control"))
	}
	if token.JSON["token_type"] != "Bearer" || token.JSON["access_token"] == "" {
		t.Fatalf("access %#v", token.JSON)
	}
	claims := verifyIDToken(t, client, issuer, fmtString(token.JSON["id_token"]))
	if claims["iss"] != issuer || claims["aud"] != "spa" || claims["nonce"] != "nonce-1" {
		t.Fatalf("id token %#v", claims)
	}
	again := postRaw(t, client, issuer+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"spa"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:9876/callback"},
		"code_verifier": {verifier},
	}, "", "", "")
	if again.StatusCode != http.StatusBadRequest || again.JSON["error"] != "invalid_grant" {
		t.Fatalf("reuse %d %#v", again.StatusCode, again.JSON)
	}

	missing := spaQuery("", "state-2", "nonce-2", "openid")
	missing.Del("code_challenge")
	missing.Del("code_challenge_method")
	badPKCE := getRaw(t, client, issuer+"/authorize/start?"+missing.Encode(), session)
	if badPKCE.StatusCode != http.StatusBadRequest || badPKCE.Header.Get("Location") != "" {
		t.Fatalf("missing pkce %d location %q", badPKCE.StatusCode, badPKCE.Header.Get("Location"))
	}
	plain := spaQuery(challenge, "state-3", "nonce-3", "openid")
	plain.Set("code_challenge_method", "plain")
	badPlain := getRaw(t, client, issuer+"/authorize/start?"+plain.Encode(), session)
	if badPlain.StatusCode != http.StatusBadRequest || badPlain.Header.Get("Location") != "" {
		t.Fatalf("plain pkce %d location %q", badPlain.StatusCode, badPlain.Header.Get("Location"))
	}
	mismatch := spaQuery(challenge, "state-4", "nonce-4", "openid")
	mismatch.Set("redirect_uri", "https://evil.example/callback")
	badRedirect := getRaw(t, client, issuer+"/authorize/start?"+mismatch.Encode(), session)
	if badRedirect.StatusCode != http.StatusBadRequest || badRedirect.Header.Get("Location") != "" {
		t.Fatalf("bad redirect %d location %q", badRedirect.StatusCode, badRedirect.Header.Get("Location"))
	}
	password := postRaw(t, client, issuer+"/token", url.Values{
		"grant_type": {"password"},
		"client_id":  {"spa"},
	}, "", "", "")
	if password.StatusCode != http.StatusBadRequest || password.JSON["error"] != "unsupported_grant_type" {
		t.Fatalf("password grant %d %#v", password.StatusCode, password.JSON)
	}

	serviceQuery := spaQuery(challenge, "svc-state", "svc-nonce", "openid")
	serviceQuery.Set("client_id", "service")
	serviceQuery.Set("redirect_uri", "https://service.local/callback")
	serviceURL := issuer + "/authorize/start?" + serviceQuery.Encode()
	serviceGrant := getRaw(t, client, serviceURL, session)
	if serviceGrant.StatusCode != http.StatusFound || strings.Contains(serviceGrant.Header.Get("Location"), "consent.html") {
		t.Fatalf("service authorize %d %s", serviceGrant.StatusCode, serviceGrant.Header.Get("Location"))
	}
	serviceCode := callbackCode(t, serviceGrant, "svc-state")
	serviceToken := postRaw(t, client, issuer+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {serviceCode},
		"redirect_uri":  {"https://service.local/callback"},
		"code_verifier": {verifier},
	}, "", "service", "dev-service-secret")
	if serviceToken.StatusCode != http.StatusOK || serviceToken.JSON["token_type"] != "Bearer" {
		t.Fatalf("service token %d %s", serviceToken.StatusCode, serviceToken.Body)
	}
	wrongSecret := postRaw(t, client, issuer+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {serviceCode},
		"redirect_uri":  {"https://service.local/callback"},
		"code_verifier": {verifier},
	}, "", "service", "wrong-secret")
	if wrongSecret.StatusCode != http.StatusUnauthorized || wrongSecret.JSON["error"] != "invalid_client" {
		t.Fatalf("bad secret %d %#v", wrongSecret.StatusCode, wrongSecret.JSON)
	}
	if !strings.Contains(wrongSecret.Header.Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("www-authenticate %q", wrongSecret.Header.Get("WWW-Authenticate"))
	}

	_, secondChallenge := pkcePair(t)
	secondQuery := spaQuery(secondChallenge, "state-5", "nonce-5", "openid profile")
	secondURL := issuer + "/authorize/start?" + secondQuery.Encode()
	skipped := getRaw(t, client, secondURL, session)
	if skipped.StatusCode != http.StatusFound || strings.Contains(skipped.Header.Get("Location"), "consent.html") {
		t.Fatalf("second authorize %d %s", skipped.StatusCode, skipped.Header.Get("Location"))
	}
	callbackCode(t, skipped, "state-5")

	silent := spaQuery(challenge, "state-6", "nonce-6", "openid")
	silent.Set("prompt", "none")
	none := getRaw(t, client, issuer+"/authorize/start?"+silent.Encode(), "")
	if none.StatusCode != http.StatusFound || !strings.Contains(none.Header.Get("Location"), "error=login_required") {
		t.Fatalf("prompt none %d %s", none.StatusCode, none.Header.Get("Location"))
	}

	flow := codeFlow(t, client, issuer, "alice@example.com", "alice", "openid")
	if flow["access_token"] == "" || flow["token_type"] != "Bearer" {
		t.Fatalf("codeFlow %#v", flow)
	}
}

func TestAdminAPI(t *testing.T) {
	client, base := testClient(t)
	issuer := base + "/restapi/v1"
	users := issuer + "/users/"

	anon := getRaw(t, client, users, "")
	if anon.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous users %d %s", anon.StatusCode, anon.Body)
	}
	session := loginSession(t, client, issuer, "alice@example.com", "alice", issuer+"/authorize/start")
	withCookie := getRaw(t, client, users, session)
	if withCookie.StatusCode != http.StatusForbidden {
		t.Fatalf("cookie users %d %s", withCookie.StatusCode, withCookie.Body)
	}
	alice := codeFlow(t, client, issuer, "alice@example.com", "alice", "openid")
	asAlice := getBearer(t, client, users, fmtString(alice["access_token"]))
	if asAlice.StatusCode != http.StatusForbidden {
		t.Fatalf("alice bearer %d %s", asAlice.StatusCode, asAlice.Body)
	}

	admin := codeFlow(t, client, issuer, "admin@example.com", "admin", "openid users-read users-write")
	token := fmtString(admin["access_token"])
	listed := getBearer(t, client, users, token)
	if listed.StatusCode != http.StatusOK {
		t.Fatalf("admin list %d %s", listed.StatusCode, listed.Body)
	}
	rows, _ := listed.JSON["results"].([]any)
	if len(rows) == 0 {
		t.Fatalf("users %#v", listed.JSON)
	}
	for _, row := range rows {
		person, _ := row.(map[string]any)
		if _, ok := person["password"]; ok {
			t.Fatalf("password leaked %#v", person)
		}
	}

	created := postJSON(t, client, users, token, map[string]any{
		"username": "cara",
		"password": "cara-secret",
	})
	if created.StatusCode != http.StatusCreated {
		t.Fatalf("create %d %s", created.StatusCode, created.Body)
	}
	for key := range created.JSON {
		if key != "id" && key != "username" && key != "status" {
			t.Fatalf("create body %#v", created.JSON)
		}
	}
	if created.JSON["username"] != "cara" || created.JSON["status"] != "active" || created.JSON["id"] == "" {
		t.Fatalf("create body %#v", created.JSON)
	}
	loginSession(t, client, issuer, "cara", "cara-secret", issuer+"/authorize/start")
}

func TestGroupScopes(t *testing.T) {
	client, base := testClient(t)
	issuer := base + "/restapi/v1"
	aliceID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa2"
	admin := codeFlow(t, client, issuer, "admin@example.com", "admin", "openid security-groups-read security-groups-write group-scopes-write group-members-read group-members-write")
	token := fmtString(admin["access_token"])

	groupID := newID(t)
	groupName := "auditors-" + groupID[:8]
	group := postObject(t, client, issuer+"/security-groups/", token, map[string]any{
		"id":   groupID,
		"name": groupName,
	})
	if group["name"] != groupName {
		t.Fatalf("group %#v", group)
	}
	scopeRow := postObject(t, client, issuer+"/group-scopes/", token, map[string]any{
		"group_id": groupID,
		"scope":    "users-read",
	})
	if scopeRow["scope"] != "users-read" {
		t.Fatalf("scope %#v", scopeRow)
	}
	member := postObject(t, client, issuer+"/group-members/", token, map[string]any{
		"group_id": groupID,
		"user_id":  aliceID,
	})
	if member["user_id"] != aliceID {
		t.Fatalf("member %#v", member)
	}

	granted := codeFlow(t, client, issuer, "alice@example.com", "alice", "openid users-read users-write")
	scope := tokenScope(t, granted)
	if !strings.Contains(scope, "users-read") || strings.Contains(scope, "users-write") {
		t.Fatalf("granted scope %q body %#v", scope, granted)
	}
	if granted["scope"] == nil {
		t.Fatalf("token JSON missing scope %#v", granted)
	}
	listed := getBearer(t, client, issuer+"/users/", fmtString(granted["access_token"]))
	if listed.StatusCode != http.StatusOK {
		t.Fatalf("alice list %d %s", listed.StatusCode, listed.Body)
	}

	removed := deleteBearer(t, client, issuer+"/group-members/"+groupID+":"+aliceID+"/", token)
	if removed.StatusCode != http.StatusNoContent && removed.StatusCode != http.StatusOK {
		t.Fatalf("remove member %d %s", removed.StatusCode, removed.Body)
	}
	narrowed := codeFlow(t, client, issuer, "alice@example.com", "alice", "openid users-read users-write")
	scope = tokenScope(t, narrowed)
	if strings.Contains(scope, "users-read") {
		t.Fatalf("scope still granted %q", scope)
	}
	if narrowed["scope"] == nil {
		t.Fatalf("narrowed token JSON %#v", narrowed)
	}
	denied := getBearer(t, client, issuer+"/users/", fmtString(narrowed["access_token"]))
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("alice after removal %d %s", denied.StatusCode, denied.Body)
	}
}

func TestUserInfo(t *testing.T) {
	client, base := testClient(t)
	issuer := base + "/restapi/v1"
	claimsURL := issuer + "/userinfo/claims"
	profileURL := issuer + "/me/profile"
	alice := codeFlow(t, client, issuer, "alice@example.com", "alice", "openid profile email groups")
	token := fmtString(alice["access_token"])
	idSub := fmtString(decodeJWTPart(t, strings.Split(fmtString(alice["id_token"]), ".")[1])["sub"])

	info := getBearer(t, client, claimsURL, token)
	if info.StatusCode != http.StatusOK {
		t.Fatalf("userinfo %d %s", info.StatusCode, info.Body)
	}
	if info.JSON["sub"] != idSub || info.JSON["given_name"] != "Alice" || info.JSON["email"] != "alice@example.com" || info.JSON["email_verified"] != true {
		t.Fatalf("userinfo %#v", info.JSON)
	}
	if !stringListContains(info.JSON["groups"], "members") {
		t.Fatalf("groups %#v", info.JSON["groups"])
	}
	posted := postJSON(t, client, claimsURL, token, map[string]any{})
	if posted.StatusCode != http.StatusOK || posted.JSON["sub"] != idSub || posted.JSON["email"] != "alice@example.com" {
		t.Fatalf("userinfo post %d %#v", posted.StatusCode, posted.JSON)
	}

	bare := codeFlow(t, client, issuer, "alice@example.com", "alice", "openid")
	only := getBearer(t, client, claimsURL, fmtString(bare["access_token"]))
	if only.StatusCode != http.StatusOK || only.JSON["sub"] == "" || only.JSON["email"] != nil || only.JSON["given_name"] != nil || only.JSON["groups"] != nil {
		t.Fatalf("openid only %#v", only.JSON)
	}

	profileOnly := codeFlow(t, client, issuer, "alice@example.com", "alice", "profile")
	forbidden := getBearer(t, client, claimsURL, fmtString(profileOnly["access_token"]))
	if forbidden.StatusCode != http.StatusForbidden {
		t.Fatalf("no openid %d %s", forbidden.StatusCode, forbidden.Body)
	}

	session := loginSession(t, client, issuer, "alice@example.com", "alice", issuer+"/authorize/start")
	renamed := putJSON(t, client, profileURL, "", session, profileBody("Alicia"))
	if renamed.StatusCode != http.StatusOK || renamed.JSON["given_name"] != "Alicia" {
		t.Fatalf("cookie profile %d %#v", renamed.StatusCode, renamed.JSON)
	}
	seen := getRaw(t, client, profileURL, session)
	if seen.JSON["given_name"] != "Alicia" {
		t.Fatalf("cookie read %#v", seen.JSON)
	}
	byToken := putJSON(t, client, profileURL, token, "", profileBody("Ally"))
	if byToken.StatusCode != http.StatusOK || byToken.JSON["given_name"] != "Ally" {
		t.Fatalf("bearer profile %d %#v", byToken.StatusCode, byToken.JSON)
	}
	putJSON(t, client, profileURL, token, "", profileBody("Alice"))

	hidden := getBearer(t, client, issuer+"/profiles/", token)
	if hidden.StatusCode != http.StatusForbidden {
		t.Fatalf("alice profiles %d %s", hidden.StatusCode, hidden.Body)
	}
	admin := codeFlow(t, client, issuer, "admin@example.com", "admin", "openid profiles-read")
	listed := getBearer(t, client, issuer+"/profiles/", fmtString(admin["access_token"]))
	if listed.StatusCode != http.StatusOK || !profileListHasEmail(listed.JSON["results"], "admin@example.com") {
		t.Fatalf("admin profiles %d %s", listed.StatusCode, listed.Body)
	}
}

func TestPasswordChange(t *testing.T) {
	client, base := testClient(t)
	issuer := base + "/restapi/v1"
	passwordURL := issuer + "/me/password"
	t.Cleanup(func() {
		logged := postRaw(t, client, issuer+"/login/", url.Values{
			"email": {"alice@example.com"}, "password": {"alice-new"}, "next": {issuer + "/authorize/start"},
		}, "", "", "")
		if logged.StatusCode != http.StatusFound || logged.Cookies["session"] == nil {
			return
		}
		postRaw(t, client, passwordURL, url.Values{
			"current_password": {"alice-new"}, "new_password": {"alice"},
		}, logged.Cookies["session"].Value, "", "")
	})

	session := loginSession(t, client, issuer, "alice@example.com", "alice", issuer+"/authorize/start")
	wrong := postRaw(t, client, passwordURL, url.Values{
		"current_password": {"nope"}, "new_password": {"alice-other"},
	}, session, "", "")
	if wrong.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong current %d %s", wrong.StatusCode, wrong.Body)
	}
	loginSession(t, client, issuer, "alice@example.com", "alice", issuer+"/authorize/start")

	issued := codeFlow(t, client, issuer, "alice@example.com", "alice", "openid offline_access")
	oldRefresh := fmtString(issued["refresh_token"])
	if oldRefresh == "" {
		t.Fatalf("missing refresh %#v", issued)
	}
	changed := postRaw(t, client, passwordURL, url.Values{
		"current_password": {"alice"}, "new_password": {"alice-new"},
	}, session, "", "")
	if changed.StatusCode != http.StatusNoContent {
		t.Fatalf("change %d %s", changed.StatusCode, changed.Body)
	}
	failed := postRaw(t, client, issuer+"/login/", url.Values{
		"email": {"alice@example.com"}, "password": {"alice"}, "next": {issuer + "/authorize/start"},
	}, "", "", "")
	if failed.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old password %d %s", failed.StatusCode, failed.Body)
	}
	stale := postRaw(t, client, issuer+"/token", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {"spa"}, "refresh_token": {oldRefresh},
	}, "", "", "")
	if stale.StatusCode != http.StatusBadRequest || stale.JSON["error"] != "invalid_grant" {
		t.Fatalf("stale refresh %d %#v", stale.StatusCode, stale.JSON)
	}
	loginSession(t, client, issuer, "alice@example.com", "alice-new", issuer+"/authorize/start")

	rotated := codeFlow(t, client, issuer, "alice@example.com", "alice-new", "openid offline_access")
	first := fmtString(rotated["refresh_token"])
	next := postRaw(t, client, issuer+"/token", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {"spa"}, "refresh_token": {first},
	}, "", "", "")
	if next.StatusCode != http.StatusOK || fmtString(next.JSON["refresh_token"]) == "" {
		t.Fatalf("rotate %d %s", next.StatusCode, next.Body)
	}
	replay := postRaw(t, client, issuer+"/token", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {"spa"}, "refresh_token": {first},
	}, "", "", "")
	if replay.StatusCode != http.StatusBadRequest || replay.JSON["error"] != "invalid_grant" {
		t.Fatalf("replay %d %#v", replay.StatusCode, replay.JSON)
	}
}

func profileBody(givenName string) map[string]any {
	return map[string]any{
		"given_name":  givenName,
		"family_name": "Able",
		"middle_name": nil,
		"nickname":    nil,
		"picture":     nil,
		"locale":      nil,
		"zoneinfo":    nil,
	}
}

func stringListContains(value any, want string) bool {
	list, ok := value.([]any)
	if !ok {
		return false
	}
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func profileListHasEmail(value any, email string) bool {
	rows, ok := value.([]any)
	if !ok {
		return false
	}
	for _, row := range rows {
		item, _ := row.(map[string]any)
		if item["email"] == email {
			return true
		}
	}
	return false
}

func putJSON(t *testing.T, client *http.Client, endpoint, token, session string, body map[string]any) formResult {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPut, endpoint, strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if session != "" {
		req.AddCookie(&http.Cookie{Name: "session", Value: session})
	}
	return doRaw(t, client, req)
}

func newID(t *testing.T) string {
	t.Helper()
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatal(err)
	}
	h := hex.EncodeToString(buf[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func tokenScope(t *testing.T, token map[string]any) string {
	t.Helper()
	if text, ok := token["scope"].(string); ok && text != "" {
		return text
	}
	claims := decodeJWTPart(t, strings.Split(fmtString(token["access_token"]), ".")[1])
	return fmtString(claims["scope"])
}

func postObject(t *testing.T, client *http.Client, endpoint, token string, body map[string]any) map[string]any {
	t.Helper()
	result := postJSON(t, client, endpoint, token, body)
	if result.StatusCode != http.StatusCreated && result.StatusCode != http.StatusOK {
		t.Fatalf("post %s %d %s", endpoint, result.StatusCode, result.Body)
	}
	if result.JSON != nil && len(result.JSON) > 0 {
		return result.JSON
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(result.Body), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("post %s body %s", endpoint, result.Body)
	}
	return rows[0]
}

func deleteBearer(t *testing.T, client *http.Client, endpoint, token string) formResult {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return doRaw(t, client, req)
}

func codeFlow(t *testing.T, client *http.Client, issuer, email, password, scope string) map[string]any {
	t.Helper()
	verifier, challenge := pkcePair(t)
	query := spaQuery(challenge, "flow-state", "flow-nonce", scope)
	authURL := issuer + "/authorize/start?" + query.Encode()
	session := loginSession(t, client, issuer, email, password, authURL)
	step := getRaw(t, client, authURL, session)
	if strings.Contains(step.Header.Get("Location"), "/media/static/consent.html") {
		allowed := postRaw(t, client, issuer+"/consent/decide", url.Values{"decision": {"allow"}, "next": {authURL}}, session, "", "")
		if allowed.StatusCode != http.StatusFound {
			t.Fatalf("codeFlow consent %d %s", allowed.StatusCode, allowed.Body)
		}
		step = getRaw(t, client, authURL, session)
	}
	code := callbackCode(t, step, "flow-state")
	token := postRaw(t, client, issuer+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"spa"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:9876/callback"},
		"code_verifier": {verifier},
	}, "", "", "")
	if token.StatusCode != http.StatusOK {
		t.Fatalf("codeFlow token %d %s", token.StatusCode, token.Body)
	}
	return token.JSON
}

func spaQuery(challenge, state, nonce, scope string) url.Values {
	values := url.Values{
		"response_type":         {"code"},
		"client_id":             {"spa"},
		"redirect_uri":          {"http://127.0.0.1:9876/callback"},
		"state":                 {state},
		"nonce":                 {nonce},
		"scope":                 {scope},
		"code_challenge_method": {"S256"},
	}
	if challenge != "" {
		values.Set("code_challenge", challenge)
	}
	return values
}

func pkcePair(t *testing.T) (string, string) {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func loginSession(t *testing.T, client *http.Client, issuer, email, password, next string) string {
	t.Helper()
	logged := postRaw(t, client, issuer+"/login/", url.Values{
		"email": {email}, "password": {password}, "next": {next},
	}, "", "", "")
	cookie := logged.Cookies["session"]
	if logged.StatusCode != http.StatusFound || cookie == nil || cookie.Value == "" {
		t.Fatalf("login %s %d %s", email, logged.StatusCode, logged.Body)
	}
	return cookie.Value
}

func callbackCode(t *testing.T, result formResult, state string) string {
	t.Helper()
	location := result.Header.Get("Location")
	if result.StatusCode != http.StatusFound || !strings.HasPrefix(location, "http://127.0.0.1:9876/callback") && !strings.HasPrefix(location, "https://service.local/callback") {
		t.Fatalf("callback %d %s", result.StatusCode, location)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("state") != state || parsed.Query().Get("code") == "" {
		t.Fatalf("callback query %s", location)
	}
	return parsed.Query().Get("code")
}

func verifyIDToken(t *testing.T, client *http.Client, issuer, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("id token %q", token)
	}
	header := decodeJWTPart(t, parts[0])
	if header["alg"] != "RS256" {
		t.Fatalf("id alg %#v", header["alg"])
	}
	keys := getJSON(t, client, issuer+"/jwks/public")
	list, _ := keys.JSON["keys"].([]any)
	jwk, _ := list[0].(map[string]any)
	pub := rsa.PublicKey{N: b64Big(t, fmtString(jwk["n"])), E: int(b64Big(t, fmtString(jwk["e"])).Int64())}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&pub, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatal(err)
	}
	return decodeJWTPart(t, parts[1])
}

func decodeJWTPart(t *testing.T, part string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func b64Big(t *testing.T, value string) *big.Int {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return new(big.Int).SetBytes(raw)
}

func fmtString(value any) string {
	text, _ := value.(string)
	return text
}

func getBearer(t *testing.T, client *http.Client, endpoint, token string) formResult {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return doRaw(t, client, req)
}

func postJSON(t *testing.T, client *http.Client, endpoint, token string, body map[string]any) formResult {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return doRaw(t, client, req)
}

func getRaw(t *testing.T, client *http.Client, endpoint, session string) formResult {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	if session != "" {
		req.AddCookie(&http.Cookie{Name: "session", Value: session})
	}
	return doRaw(t, client, req)
}

func postRaw(t *testing.T, client *http.Client, endpoint string, values url.Values, session, user, pass string) formResult {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if session != "" {
		req.AddCookie(&http.Cookie{Name: "session", Value: session})
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	return doRaw(t, client, req)
}

func doRaw(t *testing.T, client *http.Client, req *http.Request) formResult {
	t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	out := formResult{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Cookies:    map[string]*http.Cookie{},
		Body:       string(raw),
	}
	for _, cookie := range resp.Cookies() {
		out.Cookies[cookie.Name] = cookie
	}
	if len(raw) > 0 && raw[0] == '{' {
		if err := json.Unmarshal(raw, &out.JSON); err != nil {
			t.Fatalf("json %q: %v", raw, err)
		}
	}
	return out
}
