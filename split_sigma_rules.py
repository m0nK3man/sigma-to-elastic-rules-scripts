#!/usr/bin/env python3

import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

from ui_text import tr


PIPELINES = {
    "windows": "ecs_windows",
    "macos": "ecs_macos_esf",
    "kubernetes": "ecs_kubernetes",
    "zeek": "ecs_zeek_beats",
}


@dataclass
class RuleRecord:
    source: str
    collection: str = ""
    original_tags: list = field(default_factory=list)
    automatic_tags: list = field(default_factory=list)
    additional_tags: list = field(default_factory=list)
    bundle_file: str = ""
    title: str = ""
    rule_id: str = ""
    product: str = "unspecified"
    category: str = "unspecified"
    service: str = "unspecified"
    group: str = ""
    pipeline: str = ""
    status: str = "pending"
    output_file: str = ""
    notes: str = ""


def normalize(value):
    if value is None or value == "":
        return "unspecified"
    return str(value).strip().lower() or "unspecified"


def safe_name(value):
    value = re.sub(r"[^a-z0-9._-]+", "_", value.lower())
    return value.strip("._-") or "unspecified"


def read_rule(path, source_root, collection, additional_tags):
    relative = path.relative_to(source_root).as_posix()
    try:
        documents = [doc for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")) if doc]
    except Exception as exc:
        return RuleRecord(
            source=relative,
            collection=collection,
            group="invalid_yaml",
            status="manual_review",
            notes=f"Invalid YAML: {exc}",
        )

    if len(documents) != 1 or not isinstance(documents[0], dict):
        return RuleRecord(
            source=relative,
            collection=collection,
            group="multi_document_or_invalid",
            status="manual_review",
            notes="Expected one Sigma rule document per file",
        )

    rule = documents[0]
    logsource = rule.get("logsource") or {}
    if not isinstance(logsource, dict):
        logsource = {}

    product = normalize(logsource.get("product"))
    category = normalize(logsource.get("category"))
    service = normalize(logsource.get("service"))
    group = "__".join(safe_name(part) for part in (product, category, service))
    pipeline = PIPELINES.get(product, "")

    return RuleRecord(
        source=relative,
        collection=collection,
        original_tags=rule.get("tags") or [],
        automatic_tags=automatic_tags(product, category, service, pipeline, collection),
        additional_tags=additional_tags,
        title=str(rule.get("title") or ""),
        rule_id=str(rule.get("id") or "").strip().lower(),
        product=product,
        category=category,
        service=service,
        group=group,
        pipeline=pipeline,
        status="pending" if pipeline else "manual_review",
        notes="" if pipeline else "No supported automatic ECS pipeline for this product",
    )


def resolve_source(source):
    source = Path(source).expanduser().resolve()
    if not source.is_dir():
        raise ValueError(tr('Source folder does not exist: {path}', path=source))
    collections = {'rules': 'sigma-core', 'rules-emerging-threats': 'sigma-emerging-threats'}
    for root in (source, *source.parents):
        if root.name in collections:
            return source, root, collections[root.name]
    raise ValueError(tr('Choose rules, rules-emerging-threats, or a folder inside either: {path}', path=source))


def validate_sources(sources, output=None):
    if not sources:
        raise ValueError(tr('Add at least one source folder first.'))
    resolved = []
    roots = {}
    for path in sources:
        source, root, collection = resolve_source(path)
        for previous, _, _ in resolved:
            if source == previous or source in previous.parents or previous in source.parents:
                raise ValueError(tr('These source folders overlap: {first} and {second}', first=previous, second=source))
        if collection in roots and roots[collection] != root:
            raise ValueError(tr('Use folders from the same collection root for {collection}.', collection=collection))
        roots[collection] = root
        resolved.append((source, root, collection))
    if output is not None:
        output = Path(output).expanduser().resolve()
        for source, _, _ in resolved:
            if output == source or source in output.parents or output in source.parents:
                raise ValueError(tr('Source and output folders must not overlap.'))
        if output.exists() and (not output.is_dir() or any(output.iterdir())):
            raise ValueError(tr('Choose a new or empty output folder: {path}', path=output))
    return resolved


def prepare_output(output_root):
    if output_root.exists() and any(output_root.iterdir()):
        raise RuntimeError(f"Output directory is not empty: {output_root}")
    output_root.mkdir(parents=True, exist_ok=True)
    for name in ("classified", "ndjson", "bundles", "logs", "manual-review"):
        (output_root / name).mkdir()


def classify_rules(source_root, output_root, collection, additional_tags, collection_root):
    rule_paths = sorted(
        path for path in source_root.rglob("*")
        if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}
    )
    if not rule_paths:
        raise RuntimeError(f"No YAML rules found under: {source_root}")

    records = []
    for path in rule_paths:
        record = read_rule(path, collection_root, collection, additional_tags)
        records.append(record)
        destination = output_root / "classified" / collection / record.group / record.source
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
    return records


def unique_tags(tags):
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        raise RuntimeError("Tags must be strings")
    return list(dict.fromkeys(tags))


def automatic_tags(product, category, service, pipeline, collection):
    tags = [
        "custom:managed-by=sigma-splitter",
        f"custom:source={collection}",
        f"custom:product={product}",
        f"custom:category={category}",
        f"custom:pipeline={pipeline or 'manual-review'}",
    ]
    if service != "unspecified":
        tags.append(f"custom:service={service}")
    return tags


def mark_duplicates(records, output_root):
    counts = Counter(record.rule_id for record in records if record.rule_id)
    duplicates = [record for record in records if counts[record.rule_id] > 1]
    columns = ["rule_id", "title", "collection", "source", "product", "category", "service"]
    with (output_root / "manual-review" / "duplicate-rule-ids.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for record in duplicates:
            record.status = "duplicate_rule_id"
            record.notes = "All occurrences excluded; no preferred copy selected"
            writer.writerow({key: getattr(record, key) for key in columns})


def write_ndjson(path, rules):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for rule in rules:
            handle.write(json.dumps(rule, ensure_ascii=False, separators=(",", ":")) + "\n")
    temporary.replace(path)


def validate_output(path, records, seen_ids):
    by_id = {record.rule_id: record for record in records if record.rule_id}
    by_title = defaultdict(list)
    for record in records:
        if not record.rule_id:
            by_title[record.title].append(record)
    matched = []
    local_ids = set()
    matched_sources = set()
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        rule = json.loads(line)
        if not isinstance(rule, dict):
            raise RuntimeError(f"NDJSON line {number} is not a JSON object")
        rule_id = str(rule.get("rule_id") or "").strip().lower()
        if not rule_id or rule_id in local_ids or rule_id in seen_ids:
            raise RuntimeError(f"Missing or duplicate output rule_id at line {number}: {rule_id}")
        record = by_id.get(rule_id)
        if record is None:
            title = re.sub(r"^SIGMA\s*-\s*", "", str(rule.get("name") or ""), flags=re.IGNORECASE)
            candidates = by_title.get(title, [])
            if len(candidates) == 1:
                record = candidates[0]
        if record is None or record.source in matched_sources:
            raise RuntimeError(f"Output line {number} cannot be matched uniquely to a source rule")
        tags = rule.get("tags", [])
        if not isinstance(tags, list):
            raise RuntimeError(f"Invalid tags at line {number}")
        rule["tags"] = unique_tags(unique_tags(record.original_tags) + tags + record.automatic_tags + record.additional_tags)
        rule["enabled"] = False
        local_ids.add(rule_id)
        matched_sources.add(record.source)
        matched.append((record, rule))
    return matched, local_ids


def convert_groups(records, output_root, sigma_bin):
    grouped = defaultdict(list)
    for record in records:
        if record.pipeline and record.status == "pending":
            grouped[(record.collection, record.group, record.pipeline)].append(record)
    converted = []
    seen_ids = set()
    for (collection, group, pipeline), group_records in sorted(grouped.items()):
        output_file = output_root / "ndjson" / collection / f"{group}.ndjson"
        log_file = output_root / "logs" / collection / f"{group}.log"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        # Only eligible copies reach sigma-cli, including when a group has duplicate IDs.
        with tempfile.TemporaryDirectory(prefix="sigma-input-", dir=output_root) as temporary:
            source_directory = Path(temporary)
            for record in group_records:
                source = output_root / "classified" / collection / group / record.source
                destination = source_directory / record.source
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
            command = [sigma_bin, "convert", "-t", "lucene", "-p", pipeline,
                       "-f", "siem_rule_ndjson", str(source_directory),
                       "--skip-unsupported", "-o", str(output_file)]
            try:
                result = subprocess.run(command, text=True, capture_output=True, check=False)
                log_file.write_text(
                    f"Command: {' '.join(command)}\n\nSTDOUT\n{result.stdout}\nSTDERR\n{result.stderr}",
                    encoding="utf-8",
                )
                if result.returncode != 0 or not output_file.exists():
                    raise RuntimeError(f"sigma-cli failed or produced no output; see {log_file.relative_to(output_root)}")
            except (OSError, RuntimeError) as exc:
                output_file.unlink(missing_ok=True)
                for record in group_records:
                    record.status = "conversion_failed"
                    record.notes = str(exc)
                if not log_file.exists():
                    log_file.write_text(str(exc) + "\n", encoding="utf-8")
                continue
        try:
            matched, local_ids = validate_output(output_file, group_records, seen_ids)
            write_ndjson(output_file, [rule for _, rule in matched])
        except (ValueError, OSError, RuntimeError) as exc:
            output_file.unlink(missing_ok=True)
            for record in group_records:
                record.status = "validation_failed"
                record.notes = str(exc)
            with log_file.open("a", encoding="utf-8") as handle:
                handle.write(f"\nVALIDATION\n{exc}\n")
            continue
        seen_ids.update(local_ids)
        for record in group_records:
            record.status = "skipped"
            record.notes = f"Not found in output; see {log_file.relative_to(output_root)}"
        for record, rule in matched:
            record.status = "converted"
            record.notes = ""
            record.output_file = output_file.relative_to(output_root).as_posix()
            converted.append((record, rule))
    return converted


def create_bundles(converted, output_root, bundle_size):
    grouped = defaultdict(list)
    for record, rule in converted:
        grouped[(record.collection, record.product)].append((record, rule))
    seen_ids = set()
    total = 0
    for (collection, product), entries in sorted(grouped.items()):
        for offset in range(0, len(entries), bundle_size):
            part = offset // bundle_size + 1
            path = output_root / "bundles" / f"{collection}_{safe_name(product)}_part-{part:03d}.ndjson"
            chunk = entries[offset:offset + bundle_size]
            for record, rule in chunk:
                rule_id = str(rule["rule_id"]).lower()
                if rule["enabled"] is not False or rule_id in seen_ids:
                    raise RuntimeError("Bundle contains enabled rule or duplicate rule_id")
                seen_ids.add(rule_id)
                record.bundle_file = path.relative_to(output_root).as_posix()
            write_ndjson(path, [rule for _, rule in chunk])
            total += len(chunk)
    if total != len(converted):
        raise RuntimeError("Bundle count differs from converted rule count")
    return total


def write_manual_review(records, output_root):
    grouped = defaultdict(list)
    for record in records:
        if record.status == "manual_review":
            grouped[record.product].append(record)

    for product, product_records in sorted(grouped.items()):
        path = output_root / "manual-review" / f"{safe_name(product)}.txt"
        lines = [
            f"{record.collection}/{record.source}\tcategory={record.category}\tservice={record.service}\t{record.notes}"
            for record in product_records
        ]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_reports(records, output_root):
    manifest = output_root / "manifest.csv"
    fieldnames = list(asdict(records[0]).keys())
    with manifest.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            row = asdict(record)
            for key in ("original_tags", "automatic_tags", "additional_tags"):
                row[key] = json.dumps(row[key], ensure_ascii=False)
            writer.writerow(row)

    status_counts = Counter(record.status for record in records)
    product_counts = Counter(record.product for record in records)
    group_counts = Counter(record.group for record in records)
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_source_rules": len(records),
        "collection_counts": dict(sorted(Counter(record.collection for record in records).items())),
        "total_converted_rules": sum(record.status == "converted" for record in records),
        "total_bundle_rules": sum(bool(record.bundle_file) for record in records),
        "bundle_count": len({record.bundle_file for record in records if record.bundle_file}),
        "status_counts": dict(sorted(status_counts.items())),
        "product_counts": dict(sorted(product_counts.items())),
        "group_counts": dict(sorted(group_counts.items())),
    }
    (output_root / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return summary


def parse_args():
    parser = argparse.ArgumentParser(
        description="Split Sigma rules by logsource and convert supported groups."
    )
    parser.add_argument("--source", type=Path, action="append", required=True)
    parser.add_argument("--tag", action="append", default=[])
    parser.add_argument("--bundle-size", type=int, default=500)
    parser.add_argument("--output", type=Path, default=Path("sigma-separated"))
    parser.add_argument("--sigma-bin", default="sigma")
    parser.add_argument(
        "--classify-only",
        action="store_true",
        help="Only classify YAML rules and create the manifest.",
    )
    args = parser.parse_args()
    if args.bundle_size < 1:
        parser.error("--bundle-size must be a positive integer")
    return args


def main():
    args = parse_args()
    output_root = args.output.expanduser().resolve()
    try:
        sources = validate_sources(args.source, output_root)
        prepare_output(output_root)
        records = []
        for source, collection_root, collection in sources:
            records.extend(classify_rules(source, output_root, collection, unique_tags(args.tag), collection_root))
        mark_duplicates(records, output_root)
        if args.classify_only:
            for record in records:
                if record.status != "duplicate_rule_id" and record.group not in {"invalid_yaml", "multi_document_or_invalid"}:
                    record.status = "pending"
        else:
            converted = convert_groups(records, output_root, args.sigma_bin)
            create_bundles(converted, output_root, args.bundle_size)
        write_manual_review(records, output_root)
        summary = write_reports(records, output_root)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"Output: {output_root}")
    return 1 if any(record.status in {"conversion_failed", "validation_failed"} for record in records) else 0


if __name__ == "__main__":
    raise SystemExit(main())
