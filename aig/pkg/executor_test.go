package pkg

import (
	"testing"
	"time"

	sdkObject "github.com/TencentBlueKing/ci-repoAnalysis/analysis-tool-sdk-golang/object"
)

func TestBuildClientOptions_AllProvided(t *testing.T) {
	cfg := &sdkObject.ToolConfig{
		Args: []sdkObject.Argument{
			{Type: "STRING", Key: ArgKeyBaseURL, Value: "https://aig.test"},
			{Type: "STRING", Key: ArgKeyModelName, Value: "gpt-4"},
			{Type: "STRING", Key: ArgKeyModelToken, Value: "sk-x"},
			{Type: "STRING", Key: ArgKeyModelBaseURL, Value: "https://api.openai.com/v1"},
			{Type: "STRING", Key: ArgKeyPrompt, Value: "scan it"},
			{Type: "STRING", Key: ArgKeyLanguage, Value: "en"},
			{Type: "NUMBER", Key: ArgKeyThread, Value: "8"},
			{Type: "NUMBER", Key: ArgKeyUploadTimeoutSeconds, Value: "60"},
			{Type: "NUMBER", Key: ArgKeyPollIntervalSeconds, Value: "3"},
			{Type: "NUMBER", Key: ArgKeyPollTimeoutSeconds, Value: "120"},
			{Type: "NUMBER", Key: ArgKeyMaxRetries, Value: "5"},
		},
	}
	opts := buildClientOptions(cfg)
	if opts.BaseURL != "https://aig.test" {
		t.Errorf("BaseURL = %q", opts.BaseURL)
	}
	if opts.Model.Model != "gpt-4" || opts.Model.Token != "sk-x" || opts.Model.BaseURL != "https://api.openai.com/v1" {
		t.Errorf("Model = %+v", opts.Model)
	}
	if opts.Prompt != "scan it" {
		t.Errorf("Prompt = %q", opts.Prompt)
	}
	if opts.Language != "en" {
		t.Errorf("Language = %q", opts.Language)
	}
	if opts.Thread != 8 {
		t.Errorf("Thread = %d", opts.Thread)
	}
	if opts.UploadTimeout != 60*time.Second {
		t.Errorf("UploadTimeout = %s", opts.UploadTimeout)
	}
	if opts.PollInterval != 3*time.Second {
		t.Errorf("PollInterval = %s", opts.PollInterval)
	}
	if opts.PollTimeout != 120*time.Second {
		t.Errorf("PollTimeout = %s", opts.PollTimeout)
	}
	if opts.MaxRetries != 5 {
		t.Errorf("MaxRetries = %d", opts.MaxRetries)
	}
}

func TestBuildClientOptions_MissingArgsFallbackToZero(t *testing.T) {
	cfg := &sdkObject.ToolConfig{}
	opts := buildClientOptions(cfg)
	if opts.BaseURL != "" || opts.UploadTimeout != 0 || opts.PollInterval != 0 ||
		opts.PollTimeout != 0 || opts.MaxRetries != 0 || opts.Thread != 0 ||
		opts.Language != "" || opts.Prompt != "" {
		t.Errorf("expected zero ClientOptions, got %+v", opts)
	}
	// 三个 Model 字段都不应该有任何默认值兜底（包括 BaseURL）。
	if opts.Model.Model != "" || opts.Model.Token != "" || opts.Model.BaseURL != "" {
		t.Errorf("expected empty Model, got %+v", opts.Model)
	}
}

// TestBuildClientOptions_ModelBaseURLNoDefault 显式锁定本次改动的契约：
// 当调用方没有传入 modelBaseUrl 时，buildClientOptions 不会塞默认值，
// opts.Model.BaseURL 严格保持空字符串，由 HasCredentials() 在调用 server 之前拦截。
func TestBuildClientOptions_ModelBaseURLNoDefault(t *testing.T) {
	cfg := &sdkObject.ToolConfig{
		Args: []sdkObject.Argument{
			{Type: "STRING", Key: ArgKeyModelName, Value: "gpt-4"},
			{Type: "STRING", Key: ArgKeyModelToken, Value: "sk-x"},
			// 故意不传 ArgKeyModelBaseURL
		},
	}
	opts := buildClientOptions(cfg)
	if opts.Model.BaseURL != "" {
		t.Errorf("expected Model.BaseURL to stay empty (no default fallback), got %q", opts.Model.BaseURL)
	}
}

func TestBuildClientOptions_InvalidNumberIgnored(t *testing.T) {
	cfg := &sdkObject.ToolConfig{
		Args: []sdkObject.Argument{
			{Type: "NUMBER", Key: ArgKeyThread, Value: "abc"},
			{Type: "NUMBER", Key: ArgKeyUploadTimeoutSeconds, Value: "-1"},
			{Type: "NUMBER", Key: ArgKeyPollIntervalSeconds, Value: "0"},
			{Type: "NUMBER", Key: ArgKeyPollTimeoutSeconds, Value: "0"},
			{Type: "NUMBER", Key: ArgKeyMaxRetries, Value: "-2"},
		},
	}
	opts := buildClientOptions(cfg)
	if opts.Thread != 0 {
		t.Errorf("invalid number Thread should be ignored, got %d", opts.Thread)
	}
	if opts.UploadTimeout != 0 {
		t.Errorf("negative UploadTimeout should be ignored, got %s", opts.UploadTimeout)
	}
	if opts.PollInterval != 0 || opts.PollTimeout != 0 {
		t.Errorf("zero polls should be ignored, got %s/%s", opts.PollInterval, opts.PollTimeout)
	}
	if opts.MaxRetries != 0 {
		t.Errorf("negative MaxRetries should be ignored, got %d", opts.MaxRetries)
	}
}
