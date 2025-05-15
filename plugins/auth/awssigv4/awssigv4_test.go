package awssigv4

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Constants for validation tests
const (
	testAccessKeyID  = "AKIAIOSFODNN7EXAMPLE"
	testSecretKey    = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	testRegion       = "us-east-1"
	testService      = "s3"
	testDate         = "20130524"
	testDateTime     = "20130524T000000Z"
	testHost         = "examplebucket.s3.amazonaws.com"
	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	validSignature   = "f0e8bdb87c964420e8577ba39c54f57f6ad60972d7800ec6f7e2c9621b568404"
)

// testSigV4Signer is a helper to compute a signature for testing purposes,
// mirroring the plugin's internal logic directly for reliable expected values.
func testSigV4Signer(p *AWSSigV4AuthPlugin, method, path, query string, headers map[string]string, signedHeadersList []string, payloadHash, accessKey, secretKey, dateStamp, region, service, amzDate string) (string, error) {
	// Ensure signedHeadersList is sorted and lowercase, as the plugin would parse them.
	var localSignedHeaders []string
	for _, h := range signedHeadersList {
		localSignedHeaders = append(localSignedHeaders, strings.ToLower(strings.TrimSpace(h)))
	}
	sort.Strings(localSignedHeaders)

	canonicalRequest, err := p.buildCanonicalRequest(method, path, query, headers, localSignedHeaders, payloadHash)
	if err != nil {
		return "", fmt.Errorf("testSigner error building canonical request: %w", err)
	}

	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	hashedCanonicalRequest := hashSHA256([]byte(canonicalRequest))
	stringToSign := p.buildStringToSign(amzDate, credentialScope, hashedCanonicalRequest)
	signingKey := p.deriveSigningKey(secretKey, dateStamp, region, service)
	calculatedSignatureBytes := hmacSHA256(signingKey, stringToSign)
	return hex.EncodeToString(calculatedSignatureBytes), nil
}

func TestAWSSigV4AuthPlugin_Init(t *testing.T) {
	plugin := &AWSSigV4AuthPlugin{}
	settings := map[string]any{} // No specific settings for this version

	schema, err := plugin.Init(settings)
	require.NoError(t, err)
	require.NotNil(t, schema)

	assert.Equal(t, "apiKey", schema["type"])
	assert.Equal(t, "Authorization", schema["name"])
	assert.Equal(t, "header", schema["in"])
	assert.Contains(t, schema["description"], "AWS Signature Version 4")

	// Test Init with credentials
	pluginWithCreds := &AWSSigV4AuthPlugin{}
	credsSettings := map[string]any{
		"aws_access_key_id":     testAccessKeyID,
		"aws_secret_access_key": testSecretKey,
	}
	schemaWithCreds, err := pluginWithCreds.Init(credsSettings)
	require.NoError(t, err)
	require.NotNil(t, schemaWithCreds)
	assert.True(t, pluginWithCreds.PerformSignatureValidation)
	assert.Equal(t, testAccessKeyID, pluginWithCreds.ConfiguredAccessKeyID)
	assert.Equal(t, testSecretKey, pluginWithCreds.ConfiguredSecretAccessKey)
	assert.Contains(t, schemaWithCreds["description"], "If configured with credentials, this plugin also performs signature validation.")

	// Test Init with only access key id (validation should be false)
	pluginWithPartialCreds := &AWSSigV4AuthPlugin{}
	partialCredsSettings := map[string]any{
		"aws_access_key_id": testAccessKeyID,
	}
	_, err = pluginWithPartialCreds.Init(partialCredsSettings)
	require.NoError(t, err)
	assert.False(t, pluginWithPartialCreds.PerformSignatureValidation)
}

func TestAWSSigV4AuthPlugin_Authenticate(t *testing.T) {
	plugin := &AWSSigV4AuthPlugin{}
	_, err := plugin.Init(map[string]any{})
	require.NoError(t, err)

	validHeaderBase := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230301/us-east-1/execute-api/aws4_request, SignedHeaders=%s, Signature=%s"

	tests := []struct {
		name             string
		pluginSettings   map[string]any
		requestMethod    string
		requestPath      string
		requestQuery     string
		requestHeaders   map[string]string
		expectedClaims   map[string]any
		expectedErrorMsg string
	}{
		{
			name:           "valid header (parsing only)",
			requestMethod:  "GET",
			requestPath:    "/test",
			requestQuery:   "",
			pluginSettings: nil,
			requestHeaders: map[string]string{
				"Authorization": fmt.Sprintf(validHeaderBase, "host;x-amz-date", "fakesignature123"),
				"Host":          "example.com",
				"X-Amz-Date":    "20230301T000000Z",
			},
			expectedClaims: map[string]any{
				"access_key_id":  "AKIAIOSFODNN7EXAMPLE",
				"date_stamp":     "20230301",
				"region":         "us-east-1",
				"service":        "execute-api",
				"scope":          "execute-api",
				"signed_headers": []string{"host", "x-amz-date"},
				"signature":      "fakesignature123",
				"full_header":    fmt.Sprintf(validHeaderBase, "host;x-amz-date", "fakesignature123"),
			},
		},
		{
			name:           "valid header with spaces in signed_headers list and around commas (parsing only)",
			requestMethod:  "GET",
			requestPath:    "/test",
			pluginSettings: nil,
			requestHeaders: map[string]string{
				"Authorization":        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230301/us-east-1/execute-api/aws4_request ,  SignedHeaders=host; x-amz-date ; x-amz-content-sha256 ,  Signature=fakesigWithSpaces",
				"Host":                 "example.com",
				"X-Amz-Date":           "20230301T000000Z",
				"X-Amz-Content-Sha256": "somehash",
			},
			expectedClaims: map[string]any{
				"access_key_id":  "AKIAIOSFODNN7EXAMPLE",
				"date_stamp":     "20230301",
				"region":         "us-east-1",
				"service":        "execute-api",
				"scope":          "execute-api",
				"signed_headers": []string{"host", "x-amz-content-sha256", "x-amz-date"},
				"signature":      "fakesigWithSpaces",
				"full_header":    "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230301/us-east-1/execute-api/aws4_request ,  SignedHeaders=host; x-amz-date ; x-amz-content-sha256 ,  Signature=fakesigWithSpaces",
			},
		},
		{
			name:           "valid header with single signed header (parsing only)",
			requestMethod:  "GET",
			requestPath:    "/test",
			pluginSettings: nil,
			requestHeaders: map[string]string{
				"Authorization": fmt.Sprintf(validHeaderBase, "host", "fakesignatureSingle"),
				"Host":          "example.com",
			},
			expectedClaims: map[string]any{
				"access_key_id":  "AKIAIOSFODNN7EXAMPLE",
				"date_stamp":     "20230301",
				"region":         "us-east-1",
				"service":        "execute-api",
				"scope":          "execute-api",
				"signed_headers": []string{"host"},
				"signature":      "fakesignatureSingle",
				"full_header":    fmt.Sprintf(validHeaderBase, "host", "fakesignatureSingle"),
			},
		},
		{
			name:             "empty auth header value",
			requestMethod:    "GET",
			requestPath:      "/test",
			pluginSettings:   nil,
			requestHeaders:   map[string]string{"Authorization": ""},
			expectedErrorMsg: "missing authorization header",
		},
		{
			name:             "missing auth header key",
			requestMethod:    "GET",
			requestPath:      "/test",
			pluginSettings:   nil,
			requestHeaders:   map[string]string{},
			expectedErrorMsg: "missing authorization header",
		},
		{
			name:             "nil headers map",
			requestMethod:    "GET",
			requestPath:      "/test",
			pluginSettings:   nil,
			requestHeaders:   nil,
			expectedErrorMsg: "missing headers",
		},
		{
			name:             "whitespace auth header value",
			requestMethod:    "GET",
			requestPath:      "/test",
			pluginSettings:   nil,
			requestHeaders:   map[string]string{"Authorization": "   "},
			expectedErrorMsg: "missing authorization header",
		},
		{
			name:             "wrong prefix",
			requestMethod:    "GET",
			requestPath:      "/test",
			pluginSettings:   nil,
			requestHeaders:   map[string]string{"Authorization": "Basic somecreds"},
			expectedErrorMsg: "invalid authorization header format: expected prefix 'AWS4-HMAC-SHA256'",
		},
		{
			name:             "prefix only",
			requestMethod:    "GET",
			requestPath:      "/test",
			pluginSettings:   nil,
			requestHeaders:   map[string]string{"Authorization": awsSigV4Prefix + " "},
			expectedErrorMsg: "invalid AWS Signature Version 4 header format",
		},
		{
			name:             "missing credential part",
			requestMethod:    "GET",
			requestPath:      "/test",
			pluginSettings:   nil,
			requestHeaders:   map[string]string{"Authorization": awsSigV4Prefix + " SignedHeaders=host, Signature=sig"},
			expectedErrorMsg: "invalid AWS Signature Version 4 header format",
		},
		{
			name:             "malformed credential - not enough parts",
			requestMethod:    "GET",
			requestPath:      "/test",
			pluginSettings:   nil,
			requestHeaders:   map[string]string{"Authorization": awsSigV4Prefix + " Credential=AKID/20230101/us-east-1/aws4_request, SignedHeaders=host, Signature=sig"},
			expectedErrorMsg: "invalid AWS Signature Version 4 header format",
		},
		{
			name:             "malformed credential - wrong request type suffix",
			requestMethod:    "GET",
			requestPath:      "/test",
			pluginSettings:   nil,
			requestHeaders:   map[string]string{"Authorization": awsSigV4Prefix + " Credential=AKID/20230101/us-east-1/service/aws4_request_oops, SignedHeaders=host, Signature=sig"},
			expectedErrorMsg: "invalid AWS Signature Version 4 header format",
		},
		{
			name:             "missing SignedHeaders part completely",
			requestMethod:    "GET",
			requestPath:      "/test",
			pluginSettings:   nil,
			requestHeaders:   map[string]string{"Authorization": awsSigV4Prefix + " Credential=AKID/DATE/REGION/SERVICE/aws4_request, Signature=sig"},
			expectedErrorMsg: "invalid AWS Signature Version 4 header format",
		},
		{
			name:             "SignedHeaders value is empty string",
			requestMethod:    "GET",
			requestPath:      "/test",
			pluginSettings:   nil,
			requestHeaders:   map[string]string{"Authorization": fmt.Sprintf(validHeaderBase, "", "emptysignedheaderssig")},
			expectedErrorMsg: "invalid AWS Signature Version 4 header format",
		},
		{
			name:           "SignedHeaders value is only semicolons and spaces",
			requestMethod:  "GET",
			requestPath:    "/test",
			pluginSettings: nil,
			requestHeaders: map[string]string{
				"Authorization": fmt.Sprintf(validHeaderBase, " ; ;; ", "emptysignedheaderssig2"),
				"Host":          "example.com",
				"X-Amz-Date":    "20230301T000000Z",
			},
			expectedErrorMsg: "invalid AWS Signature Version 4 header: SignedHeaders list cannot be empty after parsing",
		},
		{
			name:             "missing Signature part completely",
			requestMethod:    "GET",
			requestPath:      "/test",
			pluginSettings:   nil,
			requestHeaders:   map[string]string{"Authorization": awsSigV4Prefix + " Credential=AKID/DATE/REGION/SERVICE/aws4_request, SignedHeaders=host"},
			expectedErrorMsg: "invalid AWS Signature Version 4 header format",
		},
		{
			name:             "Signature value is empty string",
			requestMethod:    "GET",
			requestPath:      "/test",
			pluginSettings:   nil,
			requestHeaders:   map[string]string{"Authorization": fmt.Sprintf(validHeaderBase, "host", "")},
			expectedErrorMsg: "invalid AWS Signature Version 4 header format",
		},
		{
			name:          "successful validation - GET empty body",
			requestMethod: "GET",
			requestPath:   "/test.txt",
			requestQuery:  "",
			pluginSettings: map[string]any{
				"aws_access_key_id":     testAccessKeyID,
				"aws_secret_access_key": testSecretKey,
			},
			requestHeaders: map[string]string{
				"Authorization":        fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s", testAccessKeyID, testDate, testRegion, testService, "f0e8bdb87c964420e8577ba39c54f57f6ad60972d7800ec6f7e2c9621b568404"),
				"host":                 testHost,
				"x-amz-date":           testDateTime,
				"x-amz-content-sha256": emptyPayloadHash,
			},
			expectedClaims: map[string]any{
				"access_key_id":  testAccessKeyID,
				"date_stamp":     testDate,
				"region":         testRegion,
				"service":        testService,
				"scope":          testService,
				"signed_headers": []string{"host", "x-amz-content-sha256", "x-amz-date"},
				"signature":      "f0e8bdb87c964420e8577ba39c54f57f6ad60972d7800ec6f7e2c9621b568404",
				"full_header":    fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s", testAccessKeyID, testDate, testRegion, testService, "f0e8bdb87c964420e8577ba39c54f57f6ad60972d7800ec6f7e2c9621b568404"),
			},
		},
		{
			name:          "failed validation - signature mismatch",
			requestMethod: "GET",
			requestPath:   "/test.txt",
			requestQuery:  "",
			pluginSettings: map[string]any{
				"aws_access_key_id":     testAccessKeyID,
				"aws_secret_access_key": testSecretKey,
			},
			requestHeaders: map[string]string{
				"Authorization":        fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s", testAccessKeyID, testDate, testRegion, testService, "invalidsignature123"),
				"host":                 testHost,
				"x-amz-date":           testDateTime,
				"x-amz-content-sha256": emptyPayloadHash,
			},
			expectedErrorMsg: "signature mismatch",
		},
		{
			name:          "failed validation - missing x-amz-date header",
			requestMethod: "GET",
			requestPath:   "/test.txt",
			pluginSettings: map[string]any{
				"aws_access_key_id":     testAccessKeyID,
				"aws_secret_access_key": testSecretKey,
			},
			requestHeaders: map[string]string{
				"Authorization": fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=host;x-amz-date, Signature=anyoldsig", testAccessKeyID, testDate, testRegion, testService),
				"host":          testHost,
			},
			expectedErrorMsg: "missing x-amz-date header, which is required for signature validation",
		},
		{
			name:          "failed validation - x-amz-date header not signed",
			requestMethod: "GET",
			requestPath:   "/test.txt",
			pluginSettings: map[string]any{
				"aws_access_key_id":     testAccessKeyID,
				"aws_secret_access_key": testSecretKey,
			},
			requestHeaders: map[string]string{
				"Authorization": fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=host, Signature=anyoldsig", testAccessKeyID, testDate, testRegion, testService),
				"host":          testHost,
				"x-amz-date":    testDateTime,
			},
			expectedErrorMsg: "x-amz-date header must be signed for signature validation",
		},
		{
			name:          "failed validation - x-amz-content-sha256 signed but not present",
			requestMethod: "GET",
			requestPath:   "/test.txt",
			pluginSettings: map[string]any{
				"aws_access_key_id":     testAccessKeyID,
				"aws_secret_access_key": testSecretKey,
			},
			requestHeaders: map[string]string{
				"Authorization": fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=anyoldsig", testAccessKeyID, testDate, testRegion, testService),
				"host":          testHost,
				"x-amz-date":    testDateTime,
			},
			expectedErrorMsg: "header x-amz-content-sha256 was signed but is not present in the request",
		},
		{
			name:          "failed validation - x-amz-content-sha256 present but not signed",
			requestMethod: "GET",
			requestPath:   "/test.txt",
			pluginSettings: map[string]any{
				"aws_access_key_id":     testAccessKeyID,
				"aws_secret_access_key": testSecretKey,
			},
			requestHeaders: map[string]string{
				"Authorization":        fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=host;x-amz-date, Signature=anyoldsig", testAccessKeyID, testDate, testRegion, testService),
				"host":                 testHost,
				"x-amz-date":           testDateTime,
				"x-amz-content-sha256": emptyPayloadHash,
			},
			expectedErrorMsg: "header x-amz-content-sha256 is present in the request but was not signed",
		},
		{
			name:          "parsing only - validation configured but access key ID mismatch",
			requestMethod: "GET",
			requestPath:   "/test.txt",
			pluginSettings: map[string]any{
				"aws_access_key_id":     "DIFFERENT_AKID",
				"aws_secret_access_key": testSecretKey,
			},
			requestHeaders: map[string]string{
				"Authorization": fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=host;x-amz-date, Signature=anyoldsig", testAccessKeyID, testDate, testRegion, testService),
				"host":          testHost,
				"x-amz-date":    testDateTime,
			},
			expectedClaims: map[string]any{
				"access_key_id":  testAccessKeyID,
				"date_stamp":     testDate,
				"region":         testRegion,
				"service":        testService,
				"scope":          testService,
				"signed_headers": []string{"host", "x-amz-date"},
				"signature":      "anyoldsig",
				"full_header":    fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=host;x-amz-date, Signature=anyoldsig", testAccessKeyID, testDate, testRegion, testService),
			},
		},
		{
			name:           "parsing only - validation not configured (no credentials)",
			requestMethod:  "GET",
			requestPath:    "/test.txt",
			pluginSettings: nil,
			requestHeaders: map[string]string{
				"Authorization": fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=host;x-amz-date, Signature=anyoldsig", testAccessKeyID, testDate, testRegion, testService),
				"host":          testHost,
				"x-amz-date":    testDateTime,
			},
			expectedClaims: map[string]any{
				"access_key_id":  testAccessKeyID,
				"date_stamp":     testDate,
				"region":         testRegion,
				"service":        testService,
				"scope":          testService,
				"signed_headers": []string{"host", "x-amz-date"},
				"signature":      "anyoldsig",
				"full_header":    fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=host;x-amz-date, Signature=anyoldsig", testAccessKeyID, testDate, testRegion, testService),
			},
		},
	}

	tempPluginForSigCalc := &AWSSigV4AuthPlugin{}
	_, initErrForSigCalc := tempPluginForSigCalc.Init(map[string]any{"aws_access_key_id": testAccessKeyID, "aws_secret_access_key": testSecretKey})
	require.NoError(t, initErrForSigCalc, "Setup: Init for sig calc failed")

	calculatedValidSignature, sigCalcErr := testSigV4Signer(tempPluginForSigCalc,
		"GET", "/test.txt", "", /* query */
		map[string]string{"host": testHost, "x-amz-date": testDateTime, "x-amz-content-sha256": emptyPayloadHash},
		[]string{"host", "x-amz-content-sha256", "x-amz-date"},
		emptyPayloadHash, testAccessKeyID, testSecretKey, testDate, testRegion, testService, testDateTime,
	)
	require.NoError(t, sigCalcErr, "Setup: Failed to pre-calculate signature for test")

	updatedCaseIndex := -1
	for i := range tests {
		if tests[i].name == "successful validation - GET empty body" {
			tests[i].requestHeaders["Authorization"] = fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s", testAccessKeyID, testDate, testRegion, testService, calculatedValidSignature)
			if tests[i].expectedClaims == nil {
				tests[i].expectedClaims = make(map[string]any)
			}
			tests[i].expectedClaims["signature"] = calculatedValidSignature
			tests[i].expectedClaims["full_header"] = tests[i].requestHeaders["Authorization"]
			updatedCaseIndex = i
			break
		}
	}
	require.NotEqual(t, -1, updatedCaseIndex, "Setup: 'successful validation - GET empty body' test case not found for update")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			currentPlugin := &AWSSigV4AuthPlugin{}
			_, initErr := currentPlugin.Init(tt.pluginSettings)
			require.NoError(t, initErr, "Plugin Init failed")

			normalizedRequestHeaders := make(map[string]string)
			if tt.requestHeaders != nil {
				for k, v := range tt.requestHeaders {
					normalizedRequestHeaders[strings.ToLower(k)] = v
				}
			} else {
				normalizedRequestHeaders = nil
			}

			claims, authErr := currentPlugin.Authenticate(normalizedRequestHeaders, tt.requestMethod, tt.requestPath, tt.requestQuery)

			if tt.expectedErrorMsg != "" {
				require.Error(t, authErr)
				assert.Contains(t, authErr.Error(), tt.expectedErrorMsg)
				assert.Nil(t, claims)
			} else {
				require.NoError(t, authErr)
				require.NotNil(t, claims)

				expectedSignedHeaders, okExp := tt.expectedClaims["signed_headers"].([]string)
				actualSignedHeaders, okAct := claims["signed_headers"].([]string)

				if okExp && okAct {
					sort.Strings(expectedSignedHeaders)
					sort.Strings(actualSignedHeaders)
					assert.ElementsMatch(t, expectedSignedHeaders, actualSignedHeaders, "SignedHeaders should match")
				} else if okExp != okAct {
					t.Errorf("Mismatched types for signed_headers. Expected: %T, Actual: %T", tt.expectedClaims["signed_headers"], claims["signed_headers"])
				}

				for k, expectedValue := range tt.expectedClaims {
					if k == "signed_headers" {
						continue
					}
					assert.Equal(t, expectedValue, claims[k], fmt.Sprintf("Claim '%s' should match", k))
				}
				assert.Equal(t, len(tt.expectedClaims), len(claims), "Number of claims should match")
			}
		})
	}
}

// Placeholder for awsSigV4Prefix if needed by adapted old tests, ensure it matches the one in awssigv4.go
// const awsSigV4Prefix = "AWS4-HMAC-SHA256" // This is already available from awssigv4.go in the same package
