#!/usr/bin/env python3
"""Validate the committed Kustomize renders for the MA-26 deployment."""
from __future__ import annotations

import sys
from typing import Any

import yaml

ALLOWED_KINDS = {
    "Cluster", "ConfigMap", "CronJob", "Deployment", "ExternalSecret", "HTTPRoute",
    "Job", "ObjectBucketClaim", "PodDisruptionBudget", "ScheduledBackup", "Service",
    "ServiceAccount",
}
FORBIDDEN_TEXT = ("my-idp-eu-central-1", "ObjectStorageClaim", "rook-ceph-block-xfs-120s", "recovery:")


def labels_at(obj: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any]:
    value: Any = obj
    for key in path:
        if not isinstance(value, dict):
            return {}
        value = value.get(key)
    return value.get("labels", {}) if isinstance(value, dict) else {}


def has_cnpg_template_label(obj: dict[str, Any]) -> bool:
    kind = obj.get("kind")
    if kind == "Pod":
        paths = [("metadata",)]
    elif kind == "CronJob":
        paths = [("spec", "jobTemplate", "spec", "template", "metadata")]
    elif kind == "Job":
        paths = [("spec", "template", "metadata")]
    elif kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"}:
        paths = [("spec", "template", "metadata")]
    else:
        return False
    for path in paths:
        if any(str(key).startswith("cnpg.io/") for key in labels_at(obj, path)):
            return True
    return False


def self_test() -> None:
    safe = {"kind": "Deployment", "spec": {"template": {"metadata": {"labels": {"app": "safe"}}}}}
    unsafe = {"kind": "Deployment", "spec": {"template": {"metadata": {"labels": {"cnpg.io/cluster": "db"}}}}}
    cron = {"kind": "CronJob", "spec": {"jobTemplate": {"spec": {"template": {"metadata": {"labels": {"cnpg.io/podRole": "instance"}}}}}}}
    assert not has_cnpg_template_label(safe)
    assert has_cnpg_template_label(unsafe)
    assert has_cnpg_template_label(cron)
    try:
        refuse_invalid_production_values("production", [{"data": {"email": "admin@placeholder.invalid"}}])
    except SystemExit:
        pass
    else:
        raise AssertionError("production .invalid placeholder was not refused")
    print("check-render self-test: PASS (CNPG pod-template labels and production placeholders refused)")


def refuse_invalid_production_values(env: str, documents: list[dict[str, Any]]) -> None:
    if env == "production":
        rendered = "\n".join(yaml.safe_dump(doc, sort_keys=False) for doc in documents if doc)
        if ".invalid" in rendered:
            raise SystemExit("production: placeholder .invalid value must be replaced before deployment")


def check(env: str, documents: list[dict[str, Any]]) -> None:
    namespace = "artifact-server" if env == "production" else "artifact-server-rehearsal"
    kinds = {doc.get("kind") for doc in documents if doc}
    unknown = sorted(kind for kind in kinds if kind not in ALLOWED_KINDS)
    if unknown:
        raise SystemExit(f"{env}: kinds outside allow-list: {unknown}")
    if "Ingress" in kinds:
        raise SystemExit(f"{env}: Ingress is forbidden; use HTTPRoute")
    for doc in documents:
        if not doc:
            continue
        if has_cnpg_template_label(doc):
            raise SystemExit(f"{env}: {doc.get('kind')} {doc.get('metadata', {}).get('name')} has a cnpg.io/ pod-template label")
        meta = doc.get("metadata") or {}
        if meta.get("namespace") != namespace:
            raise SystemExit(f"{env}: {doc.get('kind')} {meta.get('name')} has namespace {meta.get('namespace')!r}, expected {namespace}")
    text = "\n".join(yaml.safe_dump(doc, sort_keys=False) for doc in documents if doc)
    refuse_invalid_production_values(env, documents)
    for forbidden in FORBIDDEN_TEXT:
        if forbidden in text:
            raise SystemExit(f"{env}: forbidden old-cluster reference {forbidden!r}")
    for doc in documents:
        if not doc:
            continue
        def walk(value: Any, path: str = "") -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    if key == "image" and isinstance(child, str) and "@sha256:" not in child:
                        raise SystemExit(f"{env}: image is not digest-pinned at {path}: {child}")
                    walk(child, f"{path}.{key}")
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    walk(child, f"{path}[{index}]")
        walk(doc)
    clusters = [d for d in documents if d and d.get("kind") == "Cluster"]
    if len(clusters) != 1:
        raise SystemExit(f"{env}: expected exactly one CNPG Cluster, found {len(clusters)}")
    cluster = clusters[0]
    spec = cluster.get("spec", {})
    expected_instances = 3 if env == "production" else 1
    if spec.get("instances") != expected_instances:
        raise SystemExit(f"{env}: expected {expected_instances} CNPG instances")
    if not (spec.get("bootstrap") or {}).get("initdb") or spec.get("externalClusters") or "recovery" in spec.get("bootstrap", {}):
        raise SystemExit(f"{env}: CNPG must start empty through initdb")
    if "imageName" in spec or "storageClass" in spec.get("storage", {}):
        raise SystemExit(f"{env}: forbidden imageName or storage class in CNPG Cluster")
    if env == "production":
        if spec.get("postgresql", {}).get("synchronous", {}).get("dataDurability") != "required":
            raise SystemExit("production: CNPG durability must be required")
        backups = [d for d in documents if d and d.get("kind") == "ScheduledBackup"]
        if backups:
            raise SystemExit("production: ScheduledBackup waits for the admin ObjectStore and app.yaml backups declaration")
        if spec.get("plugins"):
            raise SystemExit("production: barman-cloud plug-in waits for the admin ObjectStore and app.yaml backups declaration")
        deployments = [d for d in documents if d and d.get("kind") == "Deployment" and d.get("metadata", {}).get("name") == "artifact-server"]
        if len(deployments) != 1:
            raise SystemExit("production: expected one artifact-server Deployment")
        admin_env = [e for e in deployments[0].get("spec", {}).get("template", {}).get("spec", {}).get("containers", [{}])[0].get("env", []) if e.get("name") == "ARTIFACT_SERVER_BOOTSTRAP_ADMIN_EMAIL"]
        if len(admin_env) != 1 or "value" in admin_env[0] or admin_env[0].get("valueFrom", {}).get("secretKeyRef") != {"name": "artifact-server-runtime", "key": "bootstrap-admin-email"}:
            raise SystemExit("production: bootstrap admin address must come from the carried runtime Secret")
        if not any(d and d.get("kind") == "HTTPRoute" for d in documents):
            raise SystemExit("production: expected gateway HTTPRoutes")
    else:
        if any(d and "auth.eu-central-1.myidp.cloud" in str(d) for d in documents):
            raise SystemExit("rehearsal: today's Keycloak hostname is production-only")
        if any(d and d.get("kind") in {"ScheduledBackup", "HTTPRoute"} for d in documents):
            raise SystemExit("rehearsal: backups and HTTPRoutes are forbidden")
        if any(d and d.get("kind") == "CronJob" and not (d.get("spec") or {}).get("suspend") for d in documents):
            raise SystemExit("rehearsal: every outbound worker CronJob must be suspended")
        if any(d and d.get("kind") == "ExternalSecret" and any(x.get("secretKey") == "oidc-directory-client-secret" for x in (d.get("spec", {}).get("data") or [])) for d in documents):
            raise SystemExit("rehearsal: directory client secret is forbidden")
    print(f"{env}: PASS ({len(documents)} resources; digest pins, allow-list, CNPG, routes, deferred backups and pod-label guard)")


if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
    self_test()
elif len(sys.argv) == 2 and sys.argv[1] in {"production", "rehearsal"}:
    check(sys.argv[1], list(yaml.safe_load_all(sys.stdin)))
else:
    raise SystemExit("usage: check-render.py --self-test | production | rehearsal")
