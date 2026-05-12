package pkg

import (
	"strings"
	"testing"

	"github.com/TencentBlueKing/ci-repoAnalysis/aig/pkg/aig"
)

func TestBuildSecurityResults_Empty(t *testing.T) {
	got := BuildSecurityResults("sess-1", aig.ScanResult{}, "x.zip")
	if got == nil {
		t.Fatal("expected empty slice, got nil")
	}
	if len(got) != 0 {
		t.Fatalf("expected empty results, got %d", len(got))
	}
}

func TestBuildSecurityResults_NilResultsField(t *testing.T) {
	// 显式构造一个 Results=nil 的 ScanResult，模拟 AIG 在零结果场景下
	// 不返回 results 字段（json:omitempty）的情况。
	got := BuildSecurityResults("sess-1", aig.ScanResult{Score: 100}, "x.zip")
	if got == nil || len(got) != 0 {
		t.Fatalf("expected empty (non-nil) slice, got %+v", got)
	}
}

func TestBuildSecurityResults_SingleIssue(t *testing.T) {
	scan := aig.ScanResult{
		Score: 60,
		LLM:   "kimi-k2.5",
		Results: []aig.Issue{
			{
				Title:       "Hard-coded credential",
				Description: "Token leaked in source",
				Suggestion:  "Use env var",
				Level:       "high",
				RiskType:    "credential_leak",
			},
		},
	}
	got := BuildSecurityResults("sess-1", scan, "fallback.zip")
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	r := got[0]
	if !strings.HasPrefix(r.VulId, "aig-") {
		t.Errorf("vulId must start with aig-, got %s", r.VulId)
	}
	if !strings.HasPrefix(r.VulId, vulIDPrefix) || len(r.VulId) != len(vulIDPrefix)+vulIDHashLen {
		t.Errorf("unexpected VulId shape: %s", r.VulId)
	}
	if r.VulName != "Hard-coded credential" {
		t.Errorf("VulName = %q", r.VulName)
	}
	if r.Severity != severityHigh {
		t.Errorf("Severity = %q", r.Severity)
	}
	if !strings.Contains(r.Des, "Token leaked in source") {
		t.Errorf("Des missing description: %s", r.Des)
	}
	if !strings.Contains(r.Des, "Use env var") {
		t.Errorf("Des missing suggestion: %s", r.Des)
	}
	// mcp_scan 插件不会输出 issue 级路径，Path/PkgName 直接取压缩包名 fileName。
	if r.Path != "fallback.zip" || r.PkgName != "fallback.zip" {
		t.Errorf("Path/PkgName = %s/%s, want fallback.zip", r.Path, r.PkgName)
	}
	if r.PkgVersions == nil || r.References == nil {
		t.Errorf("expected non-nil empty slices, got versions=%v refs=%v", r.PkgVersions, r.References)
	}
}

func TestBuildSecurityResults_MultiIssues(t *testing.T) {
	issues := []aig.Issue{
		{Title: "a", Level: "low"},
		{Title: "b", Level: "MEDIUM"},
		{Title: "c", Level: "Critical"},
	}
	got := BuildSecurityResults("sess-1", aig.ScanResult{Results: issues}, "x.zip")
	if len(got) != 3 {
		t.Fatalf("expected 3 results, got %d", len(got))
	}
	wantSeverity := []string{severityLow, severityMedium, severityCritical}
	for i, sr := range got {
		if sr.Severity != wantSeverity[i] {
			t.Errorf("issue[%d] severity = %q, want %q", i, sr.Severity, wantSeverity[i])
		}
		if sr.VulName != issues[i].Title {
			t.Errorf("issue[%d] vulName = %q", i, sr.VulName)
		}
		if !strings.HasPrefix(sr.VulId, "aig-") {
			t.Errorf("issue[%d] vulId missing aig- prefix: %s", i, sr.VulId)
		}
		// 所有 issue 的 Path/PkgName 都直接取 fileName，不再有 fallback 分支。
		if sr.Path != "x.zip" || sr.PkgName != "x.zip" {
			t.Errorf("issue[%d] Path/PkgName = %s/%s, want x.zip", i, sr.Path, sr.PkgName)
		}
	}
}

// TestBuildSecurityResults_RealSample 用线上抓包样本（节选）跑一遍完整链路，
// 锁定真实 mcp_scan 响应能正确生成单条 SecurityResult，并且 VulId 带 aig- 前缀。
func TestBuildSecurityResults_RealSample(t *testing.T) {
	scan := aig.ScanResult{
		Score: 60,
		Results: []aig.Issue{
			{
				Title:       "环境变量处理 Skill 意图投毒攻击",
				Description: "## 漏洞详情\n  ...",
				Suggestion:  "## 修复建议\n  ...",
				Level:       "High",
				RiskType:    "Intent Poisoning / Data Exfiltration",
			},
		},
	}
	got := BuildSecurityResults("sess-real", scan, "mcp.zip")
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	r := got[0]
	if !strings.HasPrefix(r.VulId, "aig-") {
		t.Errorf("vulId must start with aig-, got %s", r.VulId)
	}
	if len(r.VulId) != len(vulIDPrefix)+vulIDHashLen {
		t.Errorf("vulId length = %d, want %d", len(r.VulId), len(vulIDPrefix)+vulIDHashLen)
	}
	if r.Severity != severityHigh {
		t.Errorf("severity = %q", r.Severity)
	}
	if r.VulName != "环境变量处理 Skill 意图投毒攻击" {
		t.Errorf("vulName = %q", r.VulName)
	}
	if r.Path != "mcp.zip" || r.PkgName != "mcp.zip" {
		t.Errorf("expected Path/PkgName=mcp.zip, got %s/%s", r.Path, r.PkgName)
	}
}

func TestBuildSecurityResults_FallbackVulName(t *testing.T) {
	cases := []struct {
		name string
		i    aig.Issue
		want string
	}{
		{"title wins", aig.Issue{Title: "T", RiskType: "RT"}, "T"},
		{"risk_type fallback", aig.Issue{RiskType: "RT"}, "RT"},
		{"default fallback", aig.Issue{}, defaultVulName},
		{"trim spaces", aig.Issue{Title: "  ", RiskType: "  RT  "}, "RT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := BuildSecurityResults("s", aig.ScanResult{Results: []aig.Issue{c.i}}, "x")[0].VulName
			if got != c.want {
				t.Errorf("VulName = %q, want %q", got, c.want)
			}
		})
	}
}

func TestBuildSecurityResults_FallbackDescription(t *testing.T) {
	cases := []struct {
		name      string
		i         aig.Issue
		wantPart  string
		wantExact bool
	}{
		{"both empty", aig.Issue{}, defaultDescription, true},
		{"only desc", aig.Issue{Description: "danger"}, "danger", true},
		{"only sugg", aig.Issue{Suggestion: "fix me"}, suggestionPrefix + "fix me", true},
		{"both present", aig.Issue{Description: "danger", Suggestion: "fix me"}, "danger (suggestion: fix me)", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := BuildSecurityResults("s", aig.ScanResult{Results: []aig.Issue{c.i}}, "x")[0]
			if c.wantExact && r.Des != c.wantPart {
				t.Errorf("Des = %q, want %q", r.Des, c.wantPart)
			}
		})
	}
}

func TestSeverityFromLevel(t *testing.T) {
	cases := map[string]string{
		"critical":   severityCritical,
		"CRITICAL":   severityCritical,
		"malicious":  severityCritical,
		"high":       severityHigh,
		"High":       severityHigh,
		"medium":     severityMedium,
		"MEDIUM":     severityMedium,
		"suspicious": severityMedium,
		"warning":    severityMedium,
		"low":        severityLow,
		"info":       severityLow,
		"":           severityLow,
		"unknown":    severityLow,
		"  high  ":   severityHigh,
	}
	for in, want := range cases {
		if got := severityFromLevel(in); got != want {
			t.Errorf("severityFromLevel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildVulID_StableForSameInputs(t *testing.T) {
	issue := aig.Issue{Title: "T", RiskType: "R", Level: "high"}
	a := buildVulID("sess", issue)
	b := buildVulID("sess", issue)
	if a != b {
		t.Errorf("VulId not stable: %s vs %s", a, b)
	}
	if !strings.HasPrefix(a, "aig-") {
		t.Errorf("vulId must start with aig-, got %s", a)
	}
	if !strings.HasPrefix(a, vulIDPrefix) {
		t.Errorf("missing prefix constant: %s", a)
	}
	if len(a) != len(vulIDPrefix)+vulIDHashLen {
		t.Errorf("unexpected length: %d", len(a))
	}
}

func TestBuildVulID_LevelCaseInsensitive(t *testing.T) {
	a := buildVulID("s", aig.Issue{Title: "T", Level: "high"})
	b := buildVulID("s", aig.Issue{Title: "T", Level: "HIGH"})
	if a != b {
		t.Errorf("level case should not affect VulId: %s vs %s", a, b)
	}
}

func TestBuildVulID_Distinguish(t *testing.T) {
	base := buildVulID("s", aig.Issue{Title: "T", RiskType: "R", Level: "high"})
	cases := []struct {
		name string
		got  string
	}{
		{"different sessionID", buildVulID("s2", aig.Issue{Title: "T", RiskType: "R", Level: "high"})},
		{"different title", buildVulID("s", aig.Issue{Title: "T2", RiskType: "R", Level: "high"})},
		{"different riskType", buildVulID("s", aig.Issue{Title: "T", RiskType: "R2", Level: "high"})},
		{"different level", buildVulID("s", aig.Issue{Title: "T", RiskType: "R", Level: "low"})},
	}
	for _, c := range cases {
		if c.got == base {
			t.Errorf("%s: VulId should differ from base, both=%s", c.name, c.got)
		}
	}
}

func TestBuildVulID_IndependentOfDescriptionSuggestion(t *testing.T) {
	a := buildVulID("s", aig.Issue{Title: "T", Description: "v1", Suggestion: "s1"})
	b := buildVulID("s", aig.Issue{Title: "T", Description: "v2 different", Suggestion: "s2 also different"})
	if a != b {
		t.Errorf("description/suggestion should not affect VulId: %s vs %s", a, b)
	}
}
