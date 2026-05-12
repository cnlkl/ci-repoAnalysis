// Package pkg 实现 analysis-tool-sdk-golang 中定义的 Executor 接口，
// 把开源 AIG（AI-Infra-Guard）的 mcp_scan 能力包装为蓝鲸制品库扫描工具。
package pkg

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	sdkObject "github.com/TencentBlueKing/ci-repoAnalysis/analysis-tool-sdk-golang/object"

	"github.com/TencentBlueKing/ci-repoAnalysis/aig/pkg/aig"
)

// SDK 中 SecurityResult.Severity 的取值范围（小写）。
//
// 参考 ci-repoAnalysis/docs/development.md 的 result.securityResults 字段说明。
const (
	severityCritical = "critical"
	severityHigh     = "high"
	severityMedium   = "medium"
	severityLow      = "low"
)

// 默认漏洞名：当 AIG 未返回 title / risk_type 时使用。
const defaultVulName = "AIG_MCP_RISK"

// 默认描述：当 AIG 未返回 description / suggestion 时使用。
const defaultDescription = "AIG mcp scan reported a risk without further description"

// vulIDPrefix 是所有本扫描器产出的 VulId 的统一前缀。
//
// 用途：在制品库漏洞表里能一眼区分 AIG mcp_scan 与其它扫描器（trivy /
// bandit / ...）的产物；如果未来需要做来源筛选 / 批量清理，按前缀过滤即可。
// 改动该值会让历史 VulId 全部失效，请谨慎。
const vulIDPrefix = "aig-"

// vulIDHashLen 是 VulId 截取的 sha256 hex 长度（64bit，足以避免实际碰撞）。
const vulIDHashLen = 16

// suggestionPrefix 把 suggestion 拼到 description 时的前缀。
const suggestionPrefix = "suggestion: "

// BuildSecurityResults 把 AIG mcp_scan 返回的 ScanResult 转换为 SDK 标准的 SecurityResult 列表。
//
// 入参形态选择：直接接收 aig.ScanResult（即 ResultData.Result），让函数定位
// 在「把一次扫描的结果体翻译成 SDK 输出」这一概念上；任务级元信息
// （Score/Readme/StartTime 等）属于任务整体而非单条漏洞，由调用方负责打日志。
//
// 转换规则：
//  1. scan.Results 为空 → 返回空切片（即扫描没有发现风险，零结果）。
//  2. 每条 issue 输出一条 SecurityResult：
//     - VulId   = 由 sessionID + riskType + title + level 派生的稳定 ID
//     （详见 buildVulID 注释），所有 VulId 都以 "aig-" 前缀开头
//     - VulName = issue.Title；缺省时 fallback 到 risk_type / 默认值
//     - Des     = description + 可选 suggestion；都缺失时回退到 defaultDescription
//     - Severity 映射：见 severityFromLevel
//     - PkgName / Path = fileName（mcp_scan 插件不会输出文件级路径，
//     直接落在压缩包名上即可）
func BuildSecurityResults(sessionID string, scan aig.ScanResult, fileName string) []sdkObject.SecurityResult {
	if len(scan.Results) == 0 {
		return []sdkObject.SecurityResult{}
	}
	results := make([]sdkObject.SecurityResult, 0, len(scan.Results))
	for _, issue := range scan.Results {
		results = append(results, buildOneSecurityResult(sessionID, issue, fileName))
	}
	return results
}

func buildOneSecurityResult(sessionID string, issue aig.Issue, fileName string) sdkObject.SecurityResult {
	return sdkObject.SecurityResult{
		VulId:   buildVulID(sessionID, issue),
		VulName: chooseVulName(issue),
		Path:    fileName,
		PkgName: fileName,
		// 显式初始化为空切片，避免 encoding/json 把 nil slice 序列化为 null。
		// SDK 中 PkgVersions/References 没有 omitempty，服务端期望得到 [] 而非 null。
		PkgVersions: []string{},
		References:  []string{},
		Des:         buildDescription(issue),
		Severity:    severityFromLevel(issue.Level),
	}
}

// buildVulID 生成漏洞库主键 VulId。
//
// 设计目标：
//   - 稳定：同一 sessionID + 同一 issue 关键字段 → 相同 VulId，扫描器版本升级不应影响
//   - 可区分：不同 sessionID / 不同 title / 不同 risk_type / 不同 level → 不同 VulId
//   - 不依赖可变字段：description / suggestion 是自然语言，会随插件迭代变化，
//     **不**纳入 VulId 派生源
//   - 统一前缀：所有 VulId 都以 vulIDPrefix（"aig-"）开头，便于按来源筛选
//
// 派生公式：
//
//	VulId = "aig-" + sha256(sessionID|riskType|title|level)[:16]
//
// 当所有派生字段均为空时，仍能产生稳定（虽然全冲突）的 VulId。
func buildVulID(sessionID string, issue aig.Issue) string {
	parts := []string{
		strings.TrimSpace(sessionID),
		strings.TrimSpace(issue.RiskType),
		strings.TrimSpace(issue.Title),
		strings.ToLower(strings.TrimSpace(issue.Level)),
	}
	raw := strings.Join(parts, "|")
	sum := sha256.Sum256([]byte(raw))
	return vulIDPrefix + hex.EncodeToString(sum[:])[:vulIDHashLen]
}

// chooseVulName 选择 SecurityResult 的 VulName：
//
// 优先级：title > risk_type > defaultVulName。
func chooseVulName(issue aig.Issue) string {
	if t := strings.TrimSpace(issue.Title); t != "" {
		return t
	}
	if rt := strings.TrimSpace(issue.RiskType); rt != "" {
		return rt
	}
	return defaultVulName
}

// buildDescription 把 issue.Description 与 issue.Suggestion 合并为单条 Des。
//
// 规则：
//   - 优先使用 description；
//   - 当 suggestion 非空时，把它追加到末尾，形如 "<desc> (suggestion: <s>)"
//   - 两者都缺失则返回 defaultDescription
func buildDescription(issue aig.Issue) string {
	desc := strings.TrimSpace(issue.Description)
	sugg := strings.TrimSpace(issue.Suggestion)

	switch {
	case desc != "" && sugg != "":
		return desc + " (" + suggestionPrefix + sugg + ")"
	case desc != "":
		return desc
	case sugg != "":
		return suggestionPrefix + sugg
	default:
		return defaultDescription
	}
}

// severityFromLevel 把 AIG 的 level 映射到 SDK 的 severity 取值。
//
// 大小写不敏感，未识别的取值统一回退到 low。
// 同时兼容内部 AIG 使用的 malicious / suspicious 命名。
func severityFromLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical", "malicious":
		return severityCritical
	case "high":
		return severityHigh
	case "medium", "suspicious", "warning":
		return severityMedium
	default:
		return severityLow
	}
}
