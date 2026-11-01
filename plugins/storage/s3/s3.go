package s3storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// Plugin stores objects in an S3-compatible bucket.
type Plugin struct {
	host       easyrest.HostRPC
	name       string
	bucket     string
	prefix     string
	endpoint   string
	region     string
	publicBase string
	inline     bool
	pathStyle  bool
	client     *s3.Client
}

var _ easyrest.StoragePlugin = (*Plugin)(nil)

// New returns an S3 storage plugin. Init opens the bucket.
func New() *Plugin { return &Plugin{} }

// Init checks credentials, creates the bucket when it is missing, and reports inline mode.
func (p *Plugin) Init(settings map[string]any, host easyrest.HostRPC) (easyrest.StorageInfo, error) {
	p.host = host
	root, inline, err := p.initSettings(settings)
	if err != nil {
		return easyrest.StorageInfo{}, err
	}
	return easyrest.NewStorageInfo(root, inline), nil
}

func (p *Plugin) initSettings(settings map[string]any) (string, bool, error) {
	if settings == nil {
		return "", false, fmt.Errorf("storage s3: bucket is required")
	}
	if name, ok := settings["name"].(string); ok {
		p.name = name
	}
	p.bucket, _ = settings["bucket"].(string)
	p.endpoint, _ = settings["endpoint"].(string)
	p.region, _ = settings["region"].(string)
	p.prefix, _ = settings["prefix"].(string)
	p.publicBase, _ = settings["public_base"].(string)
	p.inline, _ = settings["inline"].(bool)
	access, _ := settings["access_key"].(string)
	secret, _ := settings["secret_key"].(string)
	if p.bucket == "" {
		return "", false, fmt.Errorf("storage s3: bucket is required")
	}
	if access == "" || secret == "" {
		return "", false, fmt.Errorf("storage s3: access_key and secret_key are required")
	}
	if p.region == "" {
		p.region = "us-east-1"
	}
	if pathStyle, ok := settings["path_style"].(bool); ok {
		p.pathStyle = pathStyle
	} else {
		p.pathStyle = p.endpoint != ""
	}
	p.prefix = strings.Trim(p.prefix, "/")
	p.publicBase = strings.TrimRight(p.publicBase, "/")

	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(p.region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(access, secret, "")),
		awsconfig.WithEC2IMDSClientEnableState(imds.ClientDisabled),
	)
	if err != nil {
		return "", false, fmt.Errorf("storage s3: %w", err)
	}
	p.client = s3.NewFromConfig(cfg, func(o *s3.Options) {
		if p.endpoint != "" {
			o.BaseEndpoint = aws.String(p.endpoint)
		}
		o.UsePathStyle = p.pathStyle
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})
	if err := p.ensureBucket(); err != nil {
		return "", false, err
	}
	root := p.bucket
	if p.prefix != "" {
		root = p.bucket + "/" + p.prefix
	}
	return root, p.inline, nil
}

func (p *Plugin) ensureBucket() error {
	_, err := p.client.HeadBucket(context.Background(), &s3.HeadBucketInput{Bucket: aws.String(p.bucket)})
	if err == nil {
		return nil
	}
	if !isNotFound(err) {
		return fmt.Errorf("storage s3: %w", err)
	}
	input := &s3.CreateBucketInput{Bucket: aws.String(p.bucket)}
	if p.region != "us-east-1" {
		input.CreateBucketConfiguration = &types.CreateBucketConfiguration{
			LocationConstraint: types.BucketLocationConstraint(p.region),
		}
	}
	if _, err := p.client.CreateBucket(context.Background(), input); err != nil {
		return fmt.Errorf("storage s3: %w", err)
	}
	return nil
}

// Put writes body at prefix plus the storage-relative path.
// Inline mode still writes the object and returns a data URL.
func (p *Plugin) Put(relPath string, body []byte, ctx map[string]any) (string, map[string]any, error) {
	key, rel, err := p.objectKey(relPath)
	if err != nil {
		return "", ctx, err
	}
	ctype := contentType(rel, body)
	_, err = p.client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket:      aws.String(p.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(body),
		ContentType: aws.String(ctype),
	})
	if err != nil {
		return "", ctx, fmt.Errorf("storage s3: %w", err)
	}
	if p.inline {
		return easyrest.FormatDataURL(inlineMediaType(ctype, ctx), body), ctx, nil
	}
	return rel, ctx, nil
}

// GetUrl returns a CDN URL when public_base is set, otherwise a path-style object URL.
func (p *Plugin) GetUrl(paths []string, ctx map[string]any) ([]easyrest.StorageURL, error) {
	out := make([]easyrest.StorageURL, 0, len(paths))
	for _, relPath := range paths {
		meta, err := p.GetMetadata(relPath, ctx)
		if err != nil {
			return nil, err
		}
		key, _, err := p.objectKey(relPath)
		if err != nil {
			return nil, err
		}
		out = append(out, easyrest.StorageURL{URL: p.objectURL(key), Mime: meta.Mime})
	}
	return out, nil
}

// GetMetadata reads size and MIME from the object head.
func (p *Plugin) GetMetadata(relPath string, ctx map[string]any) (easyrest.StorageMeta, error) {
	key, rel, err := p.objectKey(relPath)
	if err != nil {
		return easyrest.StorageMeta{}, err
	}
	out, err := p.client.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return easyrest.StorageMeta{}, fmt.Errorf("storage s3: %w", err)
	}
	var size int64
	if out.ContentLength != nil {
		size = *out.ContentLength
	}
	mod := time.Time{}
	if out.LastModified != nil {
		mod = *out.LastModified
	}
	mimeType := aws.ToString(out.ContentType)
	if mimeType == "" {
		mimeType = contentType(rel, nil)
	}
	return easyrest.StorageMeta{Size: size, Mime: mimeType, ModTime: mod, Created: mod}, nil
}

// GetBin downloads the object.
func (p *Plugin) GetBin(relPath string, ctx map[string]any) ([]byte, string, map[string]any, error) {
	key, rel, err := p.objectKey(relPath)
	if err != nil {
		return nil, "", ctx, err
	}
	out, err := p.client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, "", ctx, fmt.Errorf("storage s3: %w", err)
	}
	defer out.Body.Close()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, "", ctx, fmt.Errorf("storage s3: %w", err)
	}
	mimeType := aws.ToString(out.ContentType)
	if mimeType == "" {
		mimeType = contentType(rel, body)
	}
	return body, mimeType, ctx, nil
}

// List returns the immediate children of a directory. A file path returns an error.
func (p *Plugin) List(relPath string, ctx map[string]any) ([]easyrest.StorageEntry, error) {
	rel := ""
	if relPath != "" && relPath != "." {
		var err error
		_, rel, err = p.objectKey(relPath)
		if err != nil {
			return nil, err
		}
		_, err = p.client.HeadObject(context.Background(), &s3.HeadObjectInput{
			Bucket: aws.String(p.bucket),
			Key:    aws.String(p.keyFor(rel)),
		})
		if err == nil {
			return nil, fmt.Errorf("storage s3: %s is a file", rel)
		}
		if !isNotFound(err) {
			return nil, fmt.Errorf("storage s3: %w", err)
		}
	}
	listPrefix := p.keyFor(rel)
	if listPrefix != "" {
		listPrefix += "/"
	}
	page, err := p.client.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
		Bucket:    aws.String(p.bucket),
		Prefix:    aws.String(listPrefix),
		Delimiter: aws.String("/"),
	})
	if err != nil {
		return nil, fmt.Errorf("storage s3: %w", err)
	}
	if rel != "" && len(page.Contents) == 0 && len(page.CommonPrefixes) == 0 {
		return nil, fmt.Errorf("storage s3: %s not found", rel)
	}
	out := make([]easyrest.StorageEntry, 0, len(page.Contents)+len(page.CommonPrefixes))
	for _, item := range page.Contents {
		name := strings.TrimPrefix(aws.ToString(item.Key), listPrefix)
		if name == "" || strings.Contains(name, "/") {
			continue
		}
		child := name
		if rel != "" {
			child = rel + "/" + name
		}
		out = append(out, easyrest.StorageEntry{
			Name: name,
			Type: easyrest.StorageTypeFile,
			Mime: mime.TypeByExtension(path.Ext(name)),
			Path: child,
		})
	}
	for _, item := range page.CommonPrefixes {
		name := strings.TrimPrefix(aws.ToString(item.Prefix), listPrefix)
		name = strings.Trim(name, "/")
		if name == "" || strings.Contains(name, "/") {
			continue
		}
		out = append(out, easyrest.StorageEntry{Name: name, Type: easyrest.StorageTypeDir})
	}
	return out, nil
}

// Delete removes a file, or every object under a directory.
func (p *Plugin) Delete(relPath string, ctx map[string]any) error {
	key, rel, err := p.objectKey(relPath)
	if err != nil {
		return err
	}
	_, err = p.client.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(key),
	})
	if err == nil {
		_, err = p.client.DeleteObject(context.Background(), &s3.DeleteObjectInput{
			Bucket: aws.String(p.bucket),
			Key:    aws.String(key),
		})
		if err != nil {
			return fmt.Errorf("storage s3: %w", err)
		}
		return nil
	}
	if !isNotFound(err) {
		return fmt.Errorf("storage s3: %w", err)
	}
	page, err := p.client.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
		Bucket: aws.String(p.bucket),
		Prefix: aws.String(key + "/"),
	})
	if err != nil {
		return fmt.Errorf("storage s3: %w", err)
	}
	if len(page.Contents) == 0 {
		return fmt.Errorf("storage s3: %s not found", rel)
	}
	for _, item := range page.Contents {
		_, err = p.client.DeleteObject(context.Background(), &s3.DeleteObjectInput{
			Bucket: aws.String(p.bucket),
			Key:    item.Key,
		})
		if err != nil {
			return fmt.Errorf("storage s3: %w", err)
		}
	}
	return nil
}

func (p *Plugin) objectKey(relPath string) (key, rel string, err error) {
	rel, err = easyrest.CleanStorageRel(relPath)
	if err != nil {
		return "", "", err
	}
	return p.keyFor(rel), rel, nil
}

func (p *Plugin) keyFor(rel string) string {
	if p.prefix == "" {
		return rel
	}
	if rel == "" {
		return p.prefix
	}
	return p.prefix + "/" + rel
}

func (p *Plugin) objectURL(key string) string {
	if p.publicBase != "" {
		return p.publicBase + "/" + key
	}
	if p.endpoint != "" {
		return strings.TrimRight(p.endpoint, "/") + "/" + p.bucket + "/" + key
	}
	return "https://" + p.bucket + ".s3." + p.region + ".amazonaws.com/" + key
}

func inlineMediaType(detected string, ctx map[string]any) string {
	if mediaType, ok := easyrest.CtxString(ctx, easyrest.CtxStorageMIME); ok && mediaType != "" {
		return mediaType
	}
	return detected
}

func contentType(rel string, body []byte) string {
	if mt := mime.TypeByExtension(path.Ext(rel)); mt != "" {
		return mt
	}
	if len(body) == 0 {
		return "application/octet-stream"
	}
	return http.DetectContentType(body)
}

func isNotFound(err error) bool {
	var re *smithyhttp.ResponseError
	if errors.As(err, &re) && re.HTTPStatusCode() == http.StatusNotFound {
		return true
	}
	if _, ok := errors.AsType[*types.NotFound](err); ok {
		return true
	}
	if _, ok := errors.AsType[*types.NoSuchKey](err); ok {
		return true
	}
	var bucket *types.NoSuchBucket
	return errors.As(err, &bucket)
}
