"""Terraform configuration production-readiness rules.

These target .tf and .tf.json files for common security and reliability
misconfigurations. Rules use text-level pattern matching since full HCL
parsing would add a heavy dependency.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from prodogy.engine import ParsedArtifact, Rule, registry
from prodogy.models import Category, FileKind, Finding, Severity

_TERRAFORM = (FileKind.TERRAFORM,)

# Patterns for detecting resource blocks
_RESOURCE_RE = re.compile(r"^\s*resource\s+\"(\w+)\"\s+\"(\w+)\"\s*\{", re.MULTILINE)
_DATA_RE = re.compile(r"^\s*data\s+\"(\w+)\"\s+\"(\w+)\"\s*\{", re.MULTILINE)


def _find_resource_blocks(text: str, resource_type: str) -> list[tuple[str, int]]:
    """Find all blocks of a given resource type, return [(name, start_line)]."""
    pattern = re.compile(
        rf'^\s*resource\s+"{re.escape(resource_type)}"\s+"(\w+)"\s*\{{',
        re.MULTILINE,
    )
    results = []
    for m in pattern.finditer(text):
        results.append((m.group(1), text[:m.start()].count("\n") + 1))
    return results


def _block_content(text: str, start_line: int) -> str:
    """Extract the content of a brace-delimited block starting at start_line."""
    lines = text.splitlines()
    if start_line > len(lines):
        return ""
    depth = 0
    result = []
    for line in lines[start_line - 1:]:
        result.append(line)
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            break
    return "\n".join(result)


class TerraformS3EncryptionRule(Rule):
    id = "TF001"
    title = "S3 bucket server-side encryption not enabled"
    severity = Severity.ERROR
    category = Category.PRODUCTION_SAFETY
    applies_to = _TERRAFORM
    rationale = (
        "Without server-side encryption, data stored in S3 is plaintext at rest. "
        "A compromised AWS account or misconfigured bucket policy exposes all "
        "objects. AWS now enables AES-256 by default, but explicitly setting "
        "encryption is a defense-in-depth best practice."
    )
    remediation = "Add 'server_side_encryption_configuration' with AES-256 or aws:kms."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        for name, line in _find_resource_blocks(artifact.raw, "aws_s3_bucket"):
            block = _block_content(artifact.raw, line)
            if "server_side_encryption_configuration" not in block:
                yield self.finding(
                    path=artifact.path,
                    message=f"S3 bucket '{name}' has no server-side encryption configuration",
                    line=line,
                )


class TerraformS3PublicAccessRule(Rule):
    id = "TF002"
    title = "S3 bucket has public access enabled"
    severity = Severity.CRITICAL
    category = Category.PRODUCTION_SAFETY
    applies_to = _TERRAFORM
    rationale = (
        "A public S3 bucket exposes its contents to the internet. This is one "
        "of the most common causes of data breaches in AWS."
    )
    remediation = (
        "Set 'block_public_acls: true', 'block_public_policy: true', "
        "'ignore_public_acls: true', 'restrict_public_buckets: true'."
    )

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        for name, line in _find_resource_blocks(artifact.raw, "aws_s3_bucket_public_access_block"):
            block = _block_content(artifact.raw, line)
            for field in ("block_public_acls", "block_public_policy"):
                if f"{field}" not in block or "true" not in block.split(field)[-1].split("\n")[0]:
                    yield self.finding(
                        path=artifact.path,
                        message=f"S3 bucket '{name}' does not set {field}: true",
                        line=line,
                    )


class TerraformNoStateLockRule(Rule):
    id = "TF003"
    title = "Remote state backend missing encryption or locking"
    severity = Severity.WARNING
    category = Category.DEPLOY_RISK
    applies_to = _TERRAFORM
    rationale = (
        "Without state locking, concurrent Terraform runs can corrupt state. "
        "Without encryption, state (which often contains secrets) is stored "
        "in plaintext."
    )
    remediation = "Use an S3 backend with 'encrypt = true' and DynamoDB locking."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        # Check for S3 backend
        s3_re = re.compile(r'^\s*backend\s+"s3"\s*\{', re.MULTILINE)
        for m in s3_re.finditer(artifact.raw):
            block = _block_content(artifact.raw, artifact.raw[:m.start()].count("\n") + 1)
            if "encrypt" not in block or "true" not in block.split("encrypt")[-1].split("\n")[0]:
                line = artifact.raw[:m.start()].count("\n") + 1
                yield self.finding(
                    path=artifact.path,
                    message="S3 backend does not set 'encrypt = true'",
                    line=line,
                )


class TerraformRootUserRule(Rule):
    id = "TF004"
    title = "IAM policy grants root-level access"
    severity = Severity.CRITICAL
    category = Category.PRODUCTION_SAFETY
    applies_to = _TERRAFORM
    rationale = (
        "IAM policies should never grant access to '*' (all resources) with "
        "wildcard actions. This violates least-privilege and can grant "
        "unintended access to unrelated resources."
    )
    remediation = "Scope resources to specific ARNs and actions instead of using '*' wildcards."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        # Look for PolicyDocument with wildcard Resource
        for i, line in enumerate(artifact.lines, start=1):
            stripped = line.strip()
            # Match both Terraform HCL "Resource" = "*" and JSON "Resource": "*"
            if ("Resource" in stripped and '"*"' in stripped) or ("Resource" in stripped and "'*'" in stripped):
                # Check if this is inside an IAM policy context
                context = "\n".join(artifact.lines[max(0, i - 20):i])
                if "PolicyDocument" in context or "policy" in context.lower() or "iam_role" in context.lower():
                    yield self.finding(
                        path=artifact.path,
                        message="IAM policy uses wildcard Resource '*' — scope to specific ARNs",
                        line=i,
                    )


class TerraformNoLoggingRule(Rule):
    id = "TF005"
    title = "S3 bucket access logging not enabled"
    severity = Severity.WARNING
    category = Category.DEPLOY_RISK
    applies_to = _TERRAFORM
    rationale = (
        "Without access logging, you have no audit trail for who accessed or "
        "modified objects in the bucket. This makes incident forensics "
        "difficult or impossible."
    )
    remediation = "Add 'logging' block to the S3 bucket resource."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        for name, line in _find_resource_blocks(artifact.raw, "aws_s3_bucket"):
            block = _block_content(artifact.raw, line)
            if "logging" not in block:
                yield self.finding(
                    path=artifact.path,
                    message=f"S3 bucket '{name}' has no access logging configured",
                    line=line,
                )


for _rule in (
    TerraformS3EncryptionRule(),
    TerraformS3PublicAccessRule(),
    TerraformNoStateLockRule(),
    TerraformRootUserRule(),
    TerraformNoLoggingRule(),
):
    registry.register(_rule)
