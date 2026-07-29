"""Kubernetes workload production-readiness rules.

These target Deployment / StatefulSet (and bare Pod) specs. They walk the pod
spec via helpers in ``yaml_nav`` so findings can point at exact lines. Rules are
container-aware where relevant (e.g. resource limits are per-container).
"""

from __future__ import annotations

from collections.abc import Iterable

from prodogy.engine import ParsedArtifact, Rule, registry
from prodogy.models import Category, FileKind, Finding, Severity
from prodogy.rules import yaml_nav as nav

_WORKLOAD_KINDS = (
    FileKind.K8S_DEPLOYMENT,
    FileKind.K8S_STATEFULSET,
    FileKind.K8S_MANIFEST,
)

# The kubernetes "kind" values these rules care about.
_WORKLOAD_DOC_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Pod"}


def _workload_docs(artifact: ParsedArtifact):
    docs = artifact.data if isinstance(artifact.data, list) else []
    for doc in docs:
        if nav.doc_kind(doc) in _WORKLOAD_DOC_KINDS:
            yield doc


class MissingResourceLimitsRule(Rule):
    id = "K8S001"
    title = "Container missing resource requests/limits"
    severity = Severity.ERROR
    category = Category.PRODUCTION_SAFETY
    applies_to = _WORKLOAD_KINDS
    rationale = (
        "Without requests the scheduler cannot place the pod sensibly; without "
        "limits a single container can starve its node, causing noisy-neighbour "
        "outages and OOM kills of unrelated workloads."
    )
    remediation = "Set resources.requests and resources.limits for cpu and memory on every container."
    compliance_refs = ("CIS-K8s-5.4.1", "NSA-K8s-resource-limits")

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        for doc in _workload_docs(artifact):
            pod = nav.pod_spec_of(doc)
            for container, line in nav.iter_containers(pod):
                name = nav.get(container, "name", default="<unnamed>")
                resources = nav.get(container, "resources")
                requests = nav.get(resources, "requests") if resources else None
                limits = nav.get(resources, "limits") if resources else None
                missing = []
                if not requests:
                    missing.append("requests")
                if not limits:
                    missing.append("limits")
                if missing:
                    yield self.finding(
                        path=artifact.path,
                        message=f"Container '{name}' is missing resource {', '.join(missing)}",
                        line=line,
                    )


class MissingProbesRule(Rule):
    id = "K8S002"
    title = "Container missing liveness/readiness probe"
    severity = Severity.WARNING
    category = Category.DEPLOY_RISK
    applies_to = _WORKLOAD_KINDS
    rationale = (
        "Without a readiness probe, traffic is routed to pods before they can "
        "serve it, causing errors during rollouts. Without a liveness probe, a "
        "hung pod is never restarted. Suppress with '# prodogy-ok:K8S002' for "
        "workloads like batch jobs that genuinely need no probes."
    )
    remediation = "Add readinessProbe and livenessProbe appropriate to the workload."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        for doc in _workload_docs(artifact):
            if nav.doc_kind(doc) == "Pod" and nav.get(doc, "spec", "restartPolicy") in {
                "Never",
                "OnFailure",
            }:
                continue  # looks like a batch/job pod
            pod = nav.pod_spec_of(doc)
            for container, line in nav.iter_containers(pod):
                name = nav.get(container, "name", default="<unnamed>")
                missing = []
                if not nav.get(container, "readinessProbe"):
                    missing.append("readinessProbe")
                if not nav.get(container, "livenessProbe"):
                    missing.append("livenessProbe")
                if missing:
                    yield self.finding(
                        path=artifact.path,
                        message=f"Container '{name}' is missing {', '.join(missing)}",
                        line=line,
                    )


class PrivilegedContainerRule(Rule):
    id = "K8S003"
    title = "Privileged or root container"
    severity = Severity.CRITICAL
    category = Category.PRODUCTION_SAFETY
    applies_to = _WORKLOAD_KINDS
    rationale = (
        "A privileged container, or one running as UID 0, can escape to the host "
        "if compromised. This is one of the highest-impact misconfigurations in a "
        "cluster."
    )
    remediation = "Set securityContext.privileged=false, runAsNonRoot=true, and a non-zero runAsUser."
    compliance_refs = ("CIS-K8s-5.2.1", "CIS-K8s-5.2.6", "NSA-K8s-nonroot", "PCI-DSS-6.4.1")

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        for doc in _workload_docs(artifact):
            pod = nav.pod_spec_of(doc)
            pod_sc = nav.get(pod, "securityContext") or {}
            pod_nonroot = nav.get(pod_sc, "runAsNonRoot")
            for container, line in nav.iter_containers(pod):
                name = nav.get(container, "name", default="<unnamed>")
                sc = nav.get(container, "securityContext") or {}
                if nav.get(sc, "privileged") is True:
                    yield self.finding(
                        path=artifact.path,
                        message=f"Container '{name}' runs in privileged mode",
                        line=line,
                    )
                run_as = nav.get(sc, "runAsUser")
                nonroot = nav.get(sc, "runAsNonRoot")
                if nonroot is None:
                    nonroot = pod_nonroot
                if run_as == 0 or (nonroot is not True and run_as is None):
                    yield self.finding(
                        path=artifact.path,
                        message=(
                            f"Container '{name}' does not enforce runAsNonRoot "
                            "(may run as root)"
                        ),
                        line=line,
                        severity=Severity.ERROR,
                    )


class MissingAppLabelsRule(Rule):
    id = "K8S004"
    title = "Missing recommended app labels"
    severity = Severity.INFO
    category = Category.MAINTAINABILITY
    applies_to = _WORKLOAD_KINDS
    rationale = (
        "Standard labels like 'app.kubernetes.io/name' make resources "
        "discoverable, selectable, and observable. Their absence makes incident "
        "triage and ownership attribution harder later."
    )
    remediation = "Add recommended labels under metadata.labels (app.kubernetes.io/name, .../version)."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        for doc in _workload_docs(artifact):
            labels = nav.get(doc, "metadata", "labels") or {}
            has_name = any(
                k in labels for k in ("app.kubernetes.io/name", "app")
            )
            if not has_name:
                line = nav.key_line(nav.get(doc, "metadata"), "name") or nav.node_line(doc)
                name = nav.get(doc, "metadata", "name", default="<unnamed>")
                yield self.finding(
                    path=artifact.path,
                    message=f"Workload '{name}' has no app name label",
                    line=line,
                )


class DeprecatedApiVersionRule(Rule):
    id = "K8S005"
    title = "Deprecated or removed apiVersion"
    severity = Severity.ERROR
    category = Category.DEPLOY_RISK
    applies_to = _WORKLOAD_KINDS
    rationale = (
        "Removed API versions cause the manifest to be rejected outright by newer "
        "clusters, breaking deploys. Deprecated ones will break on the next "
        "upgrade — a classic latent failure."
    )
    remediation = "Migrate to the current stable apiVersion (e.g. apps/v1 for Deployments)."

    _REMOVED = {
        "extensions/v1beta1",
        "apps/v1beta1",
        "apps/v1beta2",
    }

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        docs = artifact.data if isinstance(artifact.data, list) else []
        for doc in docs:
            api = str(nav.get(doc, "apiVersion", default="") or "")
            if api in self._REMOVED:
                line = nav.key_line(doc, "apiVersion") or nav.node_line(doc)
                yield self.finding(
                    path=artifact.path,
                    message=f"apiVersion '{api}' is deprecated/removed",
                    line=line,
                )


class HostNamespaceRule(Rule):
    id = "K8S006"
    title = "Pod shares a host namespace (network/PID/IPC)"
    severity = Severity.CRITICAL
    category = Category.PRODUCTION_SAFETY
    applies_to = _WORKLOAD_KINDS
    rationale = (
        "hostNetwork, hostPID or hostIPC break the isolation boundary between a "
        "pod and its node. A compromised container can then sniff node traffic, "
        "inspect or signal host processes, and access host IPC — a direct path "
        "to node takeover and lateral movement."
    )
    remediation = "Remove hostNetwork/hostPID/hostIPC unless a specific, reviewed need exists."
    compliance_refs = ("CIS-K8s-5.2.2", "CIS-K8s-5.2.3", "CIS-K8s-5.2.4", "NSA-K8s-host-namespaces")

    _FIELDS = ("hostNetwork", "hostPID", "hostIPC")

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        for doc in _workload_docs(artifact):
            pod = nav.pod_spec_of(doc)
            if not hasattr(pod, "get"):
                continue
            for field in self._FIELDS:
                if nav.get(pod, field) is True:
                    line = nav.key_line(pod, field) or nav.node_line(pod)
                    yield self.finding(
                        path=artifact.path,
                        message=f"Pod sets {field}: true, sharing the node's namespace",
                        line=line,
                    )


class DangerousCapabilitiesRule(Rule):
    id = "K8S007"
    title = "Container adds dangerous Linux capabilities"
    severity = Severity.ERROR
    category = Category.PRODUCTION_SAFETY
    applies_to = _WORKLOAD_KINDS
    rationale = (
        "Capabilities like SYS_ADMIN, NET_ADMIN, SYS_PTRACE and NET_RAW grant "
        "near-root powers inside the container and are common building blocks for "
        "container escapes. Most workloads need none of them."
    )
    remediation = "Drop ALL capabilities and add back only the specific ones the workload requires."
    compliance_refs = ("CIS-K8s-5.2.8", "CIS-K8s-5.2.9", "NSA-K8s-capabilities")

    _DANGEROUS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "NET_RAW", "SYS_MODULE", "ALL"}

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        for doc in _workload_docs(artifact):
            pod = nav.pod_spec_of(doc)
            for container, line in nav.iter_containers(pod):
                name = nav.get(container, "name", default="<unnamed>")
                caps = nav.get(container, "securityContext", "capabilities") or {}
                added = nav.get(caps, "add") or []
                dangerous = [c for c in added if str(c).upper() in self._DANGEROUS]
                if dangerous:
                    yield self.finding(
                        path=artifact.path,
                        message=f"Container '{name}' adds dangerous capabilities: {', '.join(dangerous)}",
                        line=line,
                    )


class WritableRootFilesystemRule(Rule):
    id = "K8S008"
    title = "Container root filesystem is writable"
    severity = Severity.WARNING
    category = Category.PRODUCTION_SAFETY
    applies_to = _WORKLOAD_KINDS
    rationale = (
        "A writable root filesystem lets an attacker who gains code execution "
        "drop tools, modify binaries, or persist. An immutable root filesystem "
        "closes that avenue and is a cheap, high-value hardening step."
    )
    remediation = "Set securityContext.readOnlyRootFilesystem: true and mount writable paths as volumes."
    compliance_refs = ("CIS-K8s-5.2.11", "NSA-K8s-immutable-fs")

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        for doc in _workload_docs(artifact):
            pod = nav.pod_spec_of(doc)
            for container, line in nav.iter_containers(pod):
                name = nav.get(container, "name", default="<unnamed>")
                sc = nav.get(container, "securityContext") or {}
                if nav.get(sc, "readOnlyRootFilesystem") is not True:
                    yield self.finding(
                        path=artifact.path,
                        message=f"Container '{name}' does not set readOnlyRootFilesystem: true",
                        line=line,
                    )


class PlaintextSecretManifestRule(Rule):
    id = "K8S009"
    title = "Secret manifest contains plaintext credentials"
    severity = Severity.CRITICAL
    category = Category.CONFIDENTIAL
    applies_to = _WORKLOAD_KINDS + (FileKind.HELM_VALUES,)
    rationale = (
        "A Kubernetes Secret's stringData (or non-placeholder data) committed to "
        "a repository exposes live credentials to everyone with read access and "
        "to the full git history. Base64 in a Secret is encoding, not encryption."
    )
    remediation = (
        "Source secrets from an external manager (Vault, External Secrets Operator, "
        "sealed-secrets) instead of committing values."
    )
    compliance_refs = ("PCI-DSS-8.3", "SOC2-CC6.1", "NSA-K8s-secrets")

    _PLACEHOLDER = {"", "changeme", "example", "placeholder", "redacted", "todo", "<redacted>"}

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        docs = artifact.data if isinstance(artifact.data, list) else []
        for doc in docs:
            if nav.doc_kind(doc) != "Secret":
                continue
            string_data = nav.get(doc, "stringData") or {}
            if hasattr(string_data, "items"):
                for key, value in string_data.items():
                    v = str(value).strip().strip("\"'")
                    if v and v.lower() not in self._PLACEHOLDER and not v.startswith("${"):
                        line = nav.key_line(string_data, key) or nav.node_line(doc)
                        yield self.finding(
                            path=artifact.path,
                            message=f"Secret stringData['{key}'] holds a plaintext value",
                            line=line,
                        )


class DefaultServiceAccountTokenRule(Rule):
    id = "K8S010"
    title = "Service account token auto-mounted"
    severity = Severity.WARNING
    category = Category.PRODUCTION_SAFETY
    applies_to = _WORKLOAD_KINDS
    rationale = (
        "By default Kubernetes mounts a service account token into every pod. If "
        "the workload does not call the Kubernetes API, that token is an unused "
        "credential an attacker can steal to talk to the API server."
    )
    remediation = "Set automountServiceAccountToken: false unless the pod needs API access."
    compliance_refs = ("CIS-K8s-5.1.6", "NSA-K8s-service-account")

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        for doc in _workload_docs(artifact):
            pod = nav.pod_spec_of(doc)
            if not hasattr(pod, "get"):
                continue
            automount = nav.get(pod, "automountServiceAccountToken")
            if automount is None:
                line = nav.node_line(pod)
                yield self.finding(
                    path=artifact.path,
                    message="Pod does not set automountServiceAccountToken: false",
                    line=line,
                )


for _rule in (
    MissingResourceLimitsRule(),
    MissingProbesRule(),
    PrivilegedContainerRule(),
    MissingAppLabelsRule(),
    DeprecatedApiVersionRule(),
    HostNamespaceRule(),
    DangerousCapabilitiesRule(),
    WritableRootFilesystemRule(),
    PlaintextSecretManifestRule(),
    DefaultServiceAccountTokenRule(),
):
    registry.register(_rule)
