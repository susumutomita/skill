---
name: cloud-audit
description: AWS audit skill for auditors to analyze evidence submitted by non-auditors. Read-only operations with Amazon Q Developer CLI integration.
allowed-tools: Read, Grep, Glob, Bash
---

# AWS Audit Evidence Analysis Skill

AWS監査人が非監査人から提出されたエビデンスを読み解き、分析するための読み取り専用スキル。
Amazon Q Developer CLIを活用して効率的な証跡分析を実現します。

## 🔒 Core Principles

### READONLY-ONLY ENFORCEMENT

- **絶対禁止**: Write, Edit, 削除系コマンド (rm, delete, modify)
- **許可**: Read, Grep, Glob, Amazon Q CLI (読み取りモード)
- **原則**: 証跡の完全性を保持し、監査証跡を汚染しない

### Evidence Integrity

- 元データは一切変更しない
- 分析結果は別途ドキュメント化
- すべての操作を監査ログとして記録

## 🎯 Primary Functions

### 1. Evidence Discovery

```bash
# AWS構成ファイル、ログ、スクリーンショットの発見
Glob: **/*.json, **/*.yaml, **/*.log, **/*.png, **/*.pdf
Grep: CloudTrail, Config, IAM, SecurityHub patterns
```

### 2. Amazon Q-Powered Analysis

```bash
# Amazon Q Developer CLIで証跡を解析
q chat "このCloudTrailログから異常なAPI呼び出しを検出"
q chat "このIAMポリシーのセキュリティリスクを分析"
q chat "このAWS Config結果から非準拠リソースを特定"
```

### 3. Compliance Verification

- CIS Benchmark準拠チェック
- NIST CSF対応状況確認
- SOC2要件マッピング
- GDPR/個人情報保護対応検証

### 4. Evidence Documentation

- 発見事項の構造化記録
- リスク評価とレーティング
- 改善提案の文書化
- 監査報告書ドラフト生成

## 📋 Workflow Patterns

### Standard Security Configuration Audit Flow

1. **Evidence Collection Review**

   ```text
   - 提出物の完全性チェック
   - AWS構成ファイルの確認
   - メタデータ検証
   ```

2. **Amazon Q Consultation**

   ```bash
   q chat "提出されたAWS構成の分析方針を提案。セキュリティ設定の妥当性を重点的に"
   ```

3. **Security Configuration Analysis**

   ```text
   - IAM: 過剰な権限、MFA未設定、クレデンシャルローテーション
   - S3: パブリックアクセス、暗号化設定、バージョニング、ライフサイクル
   - VPC: セキュリティグループ、Network ACLルール、フローログ有効化
   - EC2: IMDSv2、パブリックIP、AMI暗号化
   - RDS: 暗号化、パブリックアクセス、バックアップ設定
   - KMS: キー管理ポリシー、ローテーション
   - CloudTrail: 有効化状態、S3暗号化、ログ改ざん防止
   - Config: リソース追跡、コンプライアンスルール
   - GuardDuty/SecurityHub: 有効化、検出結果
   ```

4. **Finding Synthesis**

   ```text
   - 重要度分類 (Critical/High/Medium/Low)
   - セキュリティリスク評価
   - 改善勧告の作成
   ```

## 🛠️ Tool Usage

### Allowed Commands

```yaml
Read:
  - AWS configuration files (JSON, YAML, Terraform, CloudFormation)
  - IAM policies, role definitions
  - Security group rules, Network ACL definitions
  - Screenshots and architecture diagrams
  - Documentation and compliance reports

Grep:
  - Security misconfiguration patterns
  - Overly permissive policies (wildcards)
  - Public access configurations
  - Encryption settings
  - Compliance violations

Glob:
  - Configuration file discovery
  - Policy file inventory
  - Infrastructure-as-Code files
  - Evidence pattern matching

Bash (READONLY):
  - Amazon Q CLI (q chat, q ask)
  - jq (JSON parsing and analysis)
  - grep, awk, sed (pattern analysis)
  - cat, less, head, tail (file viewing)
  - find (file discovery)
  - cfn-lint (CloudFormation validation, readonly)
  - terraform validate (Terraform syntax check, readonly)
```

### Prohibited Commands

```yaml
NEVER:
  - rm, rmdir (deletion)
  - mv (moving files)
  - Write, Edit (modification)
  - aws cli write operations (put, create, delete, update)
  - chmod, chown (permission changes)
  - terraform apply/destroy (infrastructure changes)
  - Any command that modifies evidence or AWS resources
```

## 🔍 Common Security Configuration Analysis Patterns

### IAM Configuration Audit

```bash
# Amazon QでIAM構成分析
q chat "このIAM設定を監査し、以下を報告:
1. 過剰な権限 (AdministratorAccess, Wildcard使用)
2. MFA未設定のユーザー
3. 未使用のアクセスキー
4. クレデンシャルローテーションポリシー
5. 最小権限原則違反
6. 改善提案"

# 危険なパターン検索
grep -E '(\*:\*|"Resource": "\*"|"Action": "\*"|AdministratorAccess)' iam-*.json
jq '.Users[] | select(.PasswordLastUsed == null)' iam-users.json
jq '.UserDetailList[] | select(.MFADevices | length == 0)' iam-credential-report.json
```

### S3 Security Configuration

```bash
# Amazon QでS3セキュリティ分析
q chat "このS3バケット構成を監査:
1. パブリックアクセス設定
2. 暗号化状態 (SSE-S3, SSE-KMS, SSE-C)
3. バージョニング有効化
4. ログ記録設定
5. ライフサイクルポリシー
6. バケットポリシーの妥当性"

# パブリックアクセスチェック
jq '.[] | select(.PublicAccessBlockConfiguration.BlockPublicAcls == false)' s3-buckets.json
grep -i "Principal.*\*" s3-bucket-policies.json
jq '.[] | select(.ServerSideEncryptionConfiguration == null)' s3-buckets.json
```

### VPC Network Security Audit

```bash
# Amazon QでVPCセキュリティ分析
q chat "このVPC構成を監査:
1. セキュリティグループ: 0.0.0.0/0への過度な開放
2. Network ACL: デフォルトルールのまま使用
3. VPCフローログ有効化状態
4. 不要なポート開放 (22, 3389, 3306, 5432など)
5. インバウンド/アウトバウンドルールの妥当性"

# 危険なルール検索
grep "0.0.0.0/0" security-groups.json
jq '.SecurityGroups[] | select(.IpPermissions[].IpRanges[].CidrIp == "0.0.0.0/0") | {GroupId, GroupName, IpPermissions}' sg.json
jq '.SecurityGroups[] | select(.IpPermissions[].FromPort == 22 or .IpPermissions[].FromPort == 3389)' sg.json
```

### Encryption and Key Management

```bash
# Amazon QでKMS・暗号化設定分析
q chat "この暗号化構成を監査:
1. KMSキーローテーション有効化
2. キーポリシーの妥当性
3. 暗号化されていないリソース (EBS, RDS, S3)
4. データ転送時暗号化 (TLS/SSL)
5. キー管理権限の適切性"

# 暗号化未設定リソース検出
jq '.Volumes[] | select(.Encrypted == false)' ec2-volumes.json
jq '.DBInstances[] | select(.StorageEncrypted == false)' rds-instances.json
jq '.Keys[] | select(.KeyRotationEnabled == false)' kms-keys.json
```

### CloudTrail and Logging Configuration

```bash
# Amazon Qでロギング構成分析
q chat "このロギング構成を監査:
1. CloudTrail有効化状態 (全リージョン)
2. ログファイルの整合性検証
3. S3バケット暗号化
4. CloudWatch Logsへの配信
5. VPCフローログ有効化"

# ロギング設定確認
jq '.trailList[] | {Name, IsMultiRegionTrail, LogFileValidationEnabled, S3BucketName}' cloudtrail.json
jq '.Vpcs[] | select(.FlowLogs == null or (.FlowLogs | length == 0))' vpc-flow-logs.json
```

### Compliance Configuration Check

```bash
# Amazon QでConfig準拠性分析
q chat "AWS Config結果から:
1. 非準拠リソースの特定
2. CIS Benchmarkとの対応
3. リスクレベル評価
4. 修復手順の提案"

# 非準拠リソース抽出
jq '.ConfigRules[] | select(.ComplianceType == "NON_COMPLIANT") | {ConfigRuleName, Compliance, ResourceType}' config.json
jq '.ComplianceByConfigRule | to_entries[] | select(.value.Compliance.ComplianceType == "NON_COMPLIANT")' config-compliance.json
```

## 📊 Security Configuration Audit Reporting

### Finding Report Structure

```markdown
## Finding: [Configuration Issue Title]

**Severity**: Critical | High | Medium | Low
**Category**: IAM | Network | Encryption | Logging | Compliance
**Status**: Open | Acknowledged | Remediated
**CIS Benchmark**: [Section number if applicable]

### Description

[What configuration issue was found]

### Evidence

- Configuration File: [path]
- Resource ID: [AWS resource identifier]
- Setting: [specific configuration setting]
- Query used: [Amazon Q query or jq/grep pattern]

### Current Configuration

\`\`\`json
[Actual configuration snippet showing the issue]
\`\`\`

### Risk Assessment

**Impact**: [Security/Business impact of this misconfiguration]
**Likelihood**: [Probability of exploitation]
**Risk Score**: [Critical/High/Medium/Low]

### Recommended Configuration

\`\`\`json
[Secure configuration example]
\`\`\`

### Remediation Steps

1. **Immediate action**: [Quick fix to reduce immediate risk]
2. **Short-term**: [Proper configuration change]
3. **Long-term**: [Policy/process improvement to prevent recurrence]

### Compliance Mapping

- **CIS AWS Benchmark**: [Section]
- **NIST CSF**: [Category]
- **SOC 2**: [Control]
- **AWS Well-Architected**: [Pillar - Security]

### References

- AWS Security Best Practices: [link]
- AWS Documentation: [relevant service security docs]
- Industry Standard: [CIS, NIST, etc.]
```

### Summary Report Template

```text
# AWS Security Configuration Audit Report

**Audit Date**: [YYYY-MM-DD]
**Auditor**: [Name]
**Scope**: [AWS Account ID, Services audited]

## Executive Summary

Total Findings: [N]
- Critical: [N]
- High: [N]
- Medium: [N]
- Low: [N]

## Top Security Risks

1. [Most critical finding]
2. [Second critical finding]
3. [Third critical finding]

## Findings by Category

### IAM & Access Management

- [Summary of IAM findings]

### Network Security

- [Summary of VPC/Security Group/Network ACL findings]

### Data Protection & Encryption

- [Summary of encryption findings]

### Logging & Monitoring

- [Summary of CloudTrail/Config findings]

### Compliance Status

- [Summary of compliance findings]

## Recommendations Priority

**Immediate (0-7 days)**:
1. [Critical item]

**Short-term (1-4 weeks)**:
1. [High priority item]

**Long-term (1-3 months)**:
1. [Medium priority improvement]

## Appendix

- Detailed findings
- Configuration files reviewed
- Tools and queries used
```

## 🚨 Safety Checks

### Pre-Operation Validation

```python
def validate_readonly_operation(command):
    """すべての操作前に実行"""
    forbidden = ['rm', 'write', 'edit', 'delete', 'modify', 'mv', 'chmod']
    if any(cmd in command.lower() for cmd in forbidden):
        raise SecurityError("READONLY violation detected")
    return True
```

### Evidence Chain Verification

- 提出物のハッシュ値記録
- タイムスタンプ検証
- 改ざん検出チェック

## 💡 Best Practices

### Amazon Q Integration

1. **Context-Rich Queries**: セキュリティ要件とコンプライアンス基準を含める
2. **Iterative Analysis**: 初回分析→詳細確認→追加質問のサイクル
3. **Evidence-Based**: Amazon Qの提案を実際の構成ファイルで検証

### Audit Documentation

1. すべての分析手順を記録
2. 発見事項は構成ファイルと紐付け
3. 改善提案は実装可能な具体性
4. CIS Benchmarkセクション番号を必ず記載

### Efficiency

1. Amazon Qで全体像把握→細部を手動確認
2. 共通パターンはjq/grepスクリプト化 (readonly)
3. 発見事項テンプレート活用
4. 構成ファイルの階層的レビュー (IAM→Network→Encryption→Logging)

## 📚 Common Configuration Evidence Types

### AWS Service Configuration Files

- **IAM**: Policies, Roles, Users, Groups (JSON)
- **S3**: Bucket configurations, policies (JSON)
- **VPC**: Security groups, Network ACLs, route tables (JSON)
- **EC2**: Instance configurations, AMI details (JSON)
- **RDS**: Database configurations, snapshots (JSON)
- **KMS**: Key policies, rotation settings (JSON)
- **CloudTrail**: Trail configurations (JSON)
- **AWS Config**: Rule definitions, compliance status (JSON)
- **CloudFormation**: Templates (YAML/JSON)
- **Terraform**: Infrastructure as Code files (.tf)

### Documentation & Evidence

- AWS Console screenshots
- Architecture diagrams (PNG, PDF)
- Security policies (PDF)
- Compliance matrices (Excel, CSV)
- Risk assessment reports

### Previous Audit Materials

- Previous audit findings
- Remediation tracking sheets
- Change management records
- Security incident reports

## 🎓 Example Security Configuration Audit Session

```bash
# 1. Configuration file inventory
Glob: evidence/**/*.json
Glob: evidence/**/*.tf
Glob: evidence/**/*.yaml

# 2. Amazon Q: Security posture analysis
q chat "提出されたAWS構成ファイルを分析し、セキュリティ設定の問題Top 5を特定してください。
特に以下に注目:
- IAM過剰権限
- パブリックアクセス
- 暗号化未設定
- ロギング無効化
- ネットワーク開放"

# 3. IAM configuration audit
jq '.UserDetailList[] | select(.MFADevices | length == 0) | {UserName, Arn}' evidence/iam-credential-report.json
grep -E '(\*:\*|"Resource": "\*"|"Action": "\*")' evidence/iam-*.json
q chat "これらのIAM設定から最小権限原則違反とMFA未設定ユーザーを分析"

# 4. S3 security configuration
jq '.[] | select(.PublicAccessBlockConfiguration.BlockPublicAcls == false)' evidence/s3-buckets.json
jq '.[] | select(.ServerSideEncryptionConfiguration == null)' evidence/s3-buckets.json
q chat "S3バケット構成を監査し、パブリックアクセスと暗号化未設定を報告"

# 5. Network security review
jq '.SecurityGroups[] | select(.IpPermissions[].IpRanges[].CidrIp == "0.0.0.0/0")' evidence/security-groups.json
q chat "セキュリティグループで0.0.0.0/0に開放されているポートとそのリスクを評価"

# 6. CloudTrail/Config validation
jq '.trailList[] | {Name, IsMultiRegionTrail, LogFileValidationEnabled}' evidence/cloudtrail.json
q chat "CloudTrail設定の監査ログ有効性を確認"

# 7. Findings documentation and report generation
q chat "これまでの監査結果をまとめて、優先度付きの改善勧告リストを作成"
# (結果を構造化レポートとして文書化)
```

## 🔐 Security Considerations

### Auditor Responsibilities

- 構成情報の機密性維持
- 監査作業ログの記録
- 発見事項の適切な管理
- 報告の正確性と客観性

### Data Handling

- 個人情報・機密情報の適切な取り扱い
- 分析結果の暗号化保管推奨
- 監査完了後のデータ保持ポリシー遵守
- 構成ファイルの改ざん防止

### Compliance & Independence

- 監査の独立性維持
- 利益相反の回避
- 証拠の完全性保証
- トレーサビリティの確保

---

**Note**: このスキルはREADONLY操作に厳格に限定されています。
AWS構成の完全性を保持し、監査の独立性を確保することが最優先です。

*AWS Security Configuration Audit Skill v1.0 | Readonly-only | Amazon Q Enhanced*
