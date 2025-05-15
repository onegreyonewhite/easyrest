package awssigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// AWSSigV4AuthPlugin implements an authentication plugin for AWS Signature Version 4.
// This implementation focuses on parsing the Authorization header.
// Full cryptographic validation of the signature requires access to the http.Request object,
// which is typically not provided directly to a simple Authenticate(authHeader string) method.
type AWSSigV4AuthPlugin struct {
	ConfiguredAccessKeyID      string
	ConfiguredSecretAccessKey  string
	PerformSignatureValidation bool
}

// Init initializes the AWSSigV4AuthPlugin.
// It returns an OpenAPI security schema definition for AWS SigV4.
// It now also accepts 'aws_access_key_id' and 'aws_secret_access_key' in settings
// to enable server-side signature validation.
func (p *AWSSigV4AuthPlugin) Init(settings map[string]any) (map[string]any, error) {
	if keyID, ok := settings["aws_access_key_id"].(string); ok && keyID != "" {
		p.ConfiguredAccessKeyID = keyID
	}
	if secretKey, ok := settings["aws_secret_access_key"].(string); ok && secretKey != "" {
		p.ConfiguredSecretAccessKey = secretKey
	}

	if p.ConfiguredAccessKeyID != "" && p.ConfiguredSecretAccessKey != "" {
		p.PerformSignatureValidation = true
	}

	schema := map[string]any{
		"type":        "apiKey", // AWS SigV4 is a form of API key authentication.
		"name":        "Authorization",
		"in":          "header",
		"description": "AWS Signature Version 4. The header should be in the format: AWS4-HMAC-SHA256 Credential=AccessKeyID/Date/Region/Service/aws4_request, SignedHeaders=ListOfHeaders, Signature=SignatureValue. If configured with credentials, this plugin also performs signature validation.",
	}
	return schema, nil
}

const (
	awsSigV4Prefix = "AWS4-HMAC-SHA256"
)

// sigV4AuthRegex is used to parse the AWS SigV4 Authorization header.
// It captures: 1:AccessKeyID, 2:DateStamp, 3:Region, 4:Service, 5:SignedHeadersString, 6:Signature
var sigV4AuthRegex = regexp.MustCompile(
	`^` + awsSigV4Prefix + `\s+` +
		`Credential=([^/]+)/([^/]+)/([^/]+)/([^/]+)/aws4_request` + `\s*,\s*` +
		`SignedHeaders=([^,]+)` + `\s*,\s*` +
		`Signature=(.+)$`,
)

// Authenticate parses the AWS SigV4 Authorization header.
// It extracts components like AccessKeyID, Region, Service, SignedHeaders, and Signature.
// It does not perform cryptographic signature validation itself, as that requires
// the full HTTP request details (method, path, query, headers, payload).
// If the plugin is initialized with aws_access_key_id and aws_secret_access_key,
// it will attempt to validate the signature.
func (p *AWSSigV4AuthPlugin) Authenticate(headers map[string]string, method string, path string, query string) (map[string]any, error) {
	if headers == nil { // Check for nil map first
		return nil, fmt.Errorf("missing headers")
	}

	authHeader, ok := headers["authorization"] // Header names are typically lowercase in practice
	if !ok {
		authHeader, ok = headers["Authorization"] // Check original casing as a fallback
	}

	// If key is not found OR if key is found but value is empty/whitespace
	if !ok || strings.TrimSpace(authHeader) == "" {
		return nil, fmt.Errorf("missing authorization header")
	}

	if !strings.HasPrefix(authHeader, awsSigV4Prefix) {
		return nil, fmt.Errorf("invalid authorization header format: expected prefix '%s'", awsSigV4Prefix)
	}

	matches := sigV4AuthRegex.FindStringSubmatch(authHeader)
	if len(matches) != 7 { // 6 capturing groups + the full match string
		return nil, fmt.Errorf(
			"invalid AWS Signature Version 4 header format. Expected format: %s Credential=AccessKeyID/Date/Region/Service/aws4_request, SignedHeaders=..., Signature=...",
			awsSigV4Prefix,
		)
	}

	accessKeyIDFromHeader := matches[1]
	dateStampFromHeader := matches[2] // YYYYMMDD
	regionFromHeader := matches[3]
	serviceFromHeader := matches[4]
	rawSignedHeadersStr := matches[5]
	signatureFromHeader := matches[6]

	headerParts := strings.Split(rawSignedHeadersStr, ";")
	parsedSignedHeaders := make([]string, 0, len(headerParts))
	for _, h := range headerParts {
		trimmedHeader := strings.ToLower(strings.TrimSpace(h)) // Ensure signed headers are lowercase for consistent lookup
		if trimmedHeader != "" {
			parsedSignedHeaders = append(parsedSignedHeaders, trimmedHeader)
		}
	}
	if len(parsedSignedHeaders) == 0 {
		return nil, fmt.Errorf("invalid AWS Signature Version 4 header: SignedHeaders list cannot be empty after parsing")
	}
	sort.Strings(parsedSignedHeaders) // Canonicalization requires signed headers to be sorted

	// Perform signature validation if configured
	if p.PerformSignatureValidation && accessKeyIDFromHeader == p.ConfiguredAccessKeyID {
		// 1. Get X-Amz-Date header (must be present and signed for signature calculation)
		var amzDate string
		amzDateVal, amzDateOk := headers["x-amz-date"] // Check lowercase first
		if !amzDateOk {
			amzDateVal, amzDateOk = headers["X-Amz-Date"] // Fallback to original casing
		}
		if !amzDateOk {
			return nil, fmt.Errorf("missing x-amz-date header, which is required for signature validation")
		}
		amzDate = amzDateVal

		// Ensure x-amz-date is among the signed headers
		foundAmzDateSigned := slices.Contains(parsedSignedHeaders, "x-amz-date")
		if !foundAmzDateSigned {
			return nil, fmt.Errorf("x-amz-date header must be signed for signature validation")
		}

		// 2. Determine PayloadHash
		payloadHash := ""
		xAmzContentSha256HeaderSigned := slices.Contains(parsedSignedHeaders, "x-amz-content-sha256")

		actualXAmzContentSha256, actualXAmzContentSha256HeaderPresent := headers["x-amz-content-sha256"]
		if !actualXAmzContentSha256HeaderPresent {
			actualXAmzContentSha256, actualXAmzContentSha256HeaderPresent = headers["X-Amz-Content-Sha256"]
		}

		if xAmzContentSha256HeaderSigned {
			if !actualXAmzContentSha256HeaderPresent {
				return nil, fmt.Errorf("header x-amz-content-sha256 was signed but is not present in the request")
			}
			payloadHash = actualXAmzContentSha256
		} else {
			if actualXAmzContentSha256HeaderPresent {
				return nil, fmt.Errorf("header x-amz-content-sha256 is present in the request but was not signed")
			}
			// If x-amz-content-sha256 is not signed and not present, assume empty payload (e.g., GET request)
			payloadHash = hashSHA256([]byte(""))
		}

		// 3. Build Canonical Request
		// Need to pass the actual headers map and the list of signed header names (already parsed and sorted)
		canonicalRequest, err := p.buildCanonicalRequest(method, path, query, headers, parsedSignedHeaders, payloadHash)
		if err != nil {
			return nil, fmt.Errorf("error building canonical request: %w", err)
		}

		// 4. Build String to Sign
		credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStampFromHeader, regionFromHeader, serviceFromHeader)
		hashedCanonicalRequest := hashSHA256([]byte(canonicalRequest))
		stringToSign := p.buildStringToSign(amzDate, credentialScope, hashedCanonicalRequest)

		// 5. Derive Signing Key
		signingKey := p.deriveSigningKey(p.ConfiguredSecretAccessKey, dateStampFromHeader, regionFromHeader, serviceFromHeader)

		// 6. Calculate Signature
		calculatedSignatureBytes := hmacSHA256(signingKey, stringToSign)
		calculatedSignature := hex.EncodeToString(calculatedSignatureBytes)

		// 7. Compare Signatures
		if calculatedSignature != signatureFromHeader {
			return nil, fmt.Errorf("signature mismatch: expected '%s' but got '%s'", signatureFromHeader, calculatedSignature)
		}
	}

	claims := map[string]any{
		"access_key_id":  accessKeyIDFromHeader,
		"date_stamp":     dateStampFromHeader,
		"region":         regionFromHeader,
		"service":        serviceFromHeader,
		"signed_headers": parsedSignedHeaders,
		"signature":      signatureFromHeader,
		"full_header":    authHeader, // Including full_header can be useful for downstream deep validation
		"scope":          serviceFromHeader,
	}

	return claims, nil
}

// Helper functions for AWS SigV4 signing
func hashSHA256(data []byte) string {
	hasher := sha256.New()
	hasher.Write(data)
	return hex.EncodeToString(hasher.Sum(nil))
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func (p *AWSSigV4AuthPlugin) deriveSigningKey(secretKey, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	return kSigning
}

func (p *AWSSigV4AuthPlugin) buildCanonicalRequest(method, path, query string, headers map[string]string, signedHeaders []string, payloadHash string) (string, error) {
	// HTTPRequestMethod
	canonicalRequest := method + "\n"

	// CanonicalURI
	// Ensure path is not empty and starts with a /
	canonPath := path
	if canonPath == "" {
		canonPath = "/"
	}
	// URI-encode everything in the path, except for "/" if it is not already encoded.
	// Split path by / to encode each segment individually.
	segments := strings.Split(canonPath, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	canonicalRequest += strings.Join(segments, "/") + "\n"

	// CanonicalQueryString
	// Sort query parameters by name, then by value if names are the same.
	// Encode names and values.
	queryParams := url.Values{}
	if query != "" {
		parsedQuery, err := url.ParseQuery(query)
		if err != nil {
			return "", fmt.Errorf("error parsing query string: %w", err)
		}
		queryParams = parsedQuery
	}
	var sortedQueryKeys []string
	for k := range queryParams {
		sortedQueryKeys = append(sortedQueryKeys, k)
	}
	sort.Strings(sortedQueryKeys)

	var canonicalQueryParts []string
	for _, k := range sortedQueryKeys {
		values := queryParams[k]
		sort.Strings(values) // Sort values for the same key
		for _, v := range values {
			canonicalQueryParts = append(canonicalQueryParts, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	canonicalRequest += strings.Join(canonicalQueryParts, "&") + "\n"

	// CanonicalHeaders
	// Lowercase header names, trim values, sort by name.
	// Include headers that are in signedHeaders list.
	var canonicalHeaderLines []string
	var actualSignedHeaderNames []string

	// Normalize provided headers map keys to lowercase for reliable lookup
	lowerHeaders := make(map[string]string)
	for k, v := range headers {
		lowerHeaders[strings.ToLower(k)] = v
	}

	for _, headerNameLower := range signedHeaders { // signedHeaders should already be lowercase and sorted by Authorization header parsing
		value, ok := lowerHeaders[headerNameLower]
		if !ok {
			// This should ideally be caught earlier if a signed header isn't present.
			// However, for robustness, AWS examples show that 'host' might be derived if not explicitly passed.
			// For this implementation, we'll require it to be in the headers map if signed.
			return "", fmt.Errorf("signed header '%s' not found in request headers", headerNameLower)
		}
		// AWS examples: "Trim excess spaces from values and convert sequential spaces to a single space"
		// For simplicity, we'll just trim. More complex whitespace normalization might be needed for full compliance.
		canonicalHeaderLines = append(canonicalHeaderLines, headerNameLower+":"+strings.TrimSpace(value))
		actualSignedHeaderNames = append(actualSignedHeaderNames, headerNameLower)
	}
	sort.Strings(canonicalHeaderLines)                                    // Ensure they are sorted by header name (already should be if signedHeaders was sorted)
	canonicalRequest += strings.Join(canonicalHeaderLines, "\n") + "\n\n" // Extra newline after headers

	// SignedHeaders
	// Semicolon-separated list of lowercase header names, sorted.
	sort.Strings(actualSignedHeaderNames) // Ensure signedHeaders are sorted for this part
	canonicalRequest += strings.Join(actualSignedHeaderNames, ";") + "\n"

	// HashedPayload
	canonicalRequest += payloadHash

	return canonicalRequest, nil
}

func (p *AWSSigV4AuthPlugin) buildStringToSign(dateTime, credentialScope, canonicalRequestHash string) string {
	return "AWS4-HMAC-SHA256\n" +
		dateTime + "\n" +
		credentialScope + "\n" +
		canonicalRequestHash
}
