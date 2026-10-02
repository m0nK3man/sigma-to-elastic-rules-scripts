# Sigma Splitter

A terminal tool for selecting Sigma rule folders, converting supported log sources into Elastic Security NDJSON, and importing reviewed bundles through the Kibana API.

The menu supports English and Vietnamese. Add source folders one at a time, review the current setup, and run conversion or import when ready.

## Requirements

- Python 3.10 or newer.
- PyYAML, installed from `requirements.txt`.
- For conversion: `sigma-cli` with the Elasticsearch backend and the required pipelines.
- For API import: a reachable Kibana URL and credentials with appropriate permissions in the selected Space.

Classification and API import do not require sigma-cli. The menu imports the splitter, so PyYAML is required even when you only use the API features.

## Setup

Extract the project, then run these commands from its folder:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

If you need to convert rules, install the conversion tools in the same environment:

```bash
python -m pip install sigma-cli
sigma plugin install elasticsearch
sigma list pipelines
sigma list formats lucene
```

Confirm that your installed backend exposes the pipelines below and the `siem_rule_ndjson` format. Dependencies are not installed automatically by the menu.

## Start the menu

```bash
python sigma_rules_menu.py
```

Choose your language at startup, or set it explicitly:

```bash
python sigma_rules_menu.py --language en
python sigma_rules_menu.py --language vi
```

You can change the language during the session with option `13`. `SIGMA_LANGUAGE=en` or `SIGMA_LANGUAGE=vi` also selects the initial language. Menu and API messages are localized; machine-readable statuses, field names, and diagnostics returned by sigma-cli or Kibana retain their original values.

| Option | Action |
| --- | --- |
| `1` | Add or remove source folders |
| `2` | Set the output folder |
| `3` | Replace extra tags, one tag per line |
| `4` | Set the maximum rules per bundle |
| `5` | Switch between classification only and conversion |
| `6` | Set the sigma executable |
| `7` | Preview the equivalent CLI command |
| `8` | Review the setup and start conversion |
| `9` | Configure the Kibana URL, Space, and CA certificate |
| `10` | Test access to the Detection Rules API |
| `11` | Review and import a file or bundles folder |
| `12` | Set an API key or username/password, or clear credentials |
| `13` | Change language |
| `0` | Exit |

The menu starts with an empty source list. In option `1`, choose **Add a folder**, enter a path, and answer **yes** to add another. Enter a blank path to stop adding folders. Return to the main menu when your source list is ready. Relative paths are based on the directory where you started the tool. Do not add surrounding quotes to a path entered in the menu.

## Selecting source folders

Sources must be named `rules` or `rules-emerging-threats`, or be folders inside one of those collection roots.

| Collection root | Collection tag |
| --- | --- |
| `rules` | `sigma-core` |
| `rules-emerging-threats` | `sigma-emerging-threats` |

You can select a whole collection, a product folder such as `rules/windows`, or a deeper folder. Multiple non-overlapping folders from the same collection are supported, for example:

```text
rules/windows/image_load
rules/windows/process_creation
rules-emerging-threats/windows
```

A repeated folder or a parent/child pair is rejected to prevent reading the same rules twice. Sources for the same collection must share the same collection root. Only selected folders and their descendants are scanned. Rules outside that scope are not included in duplicate-ID checks.

Manifest source paths are relative to the collection root. This preserves paths such as `windows/image_load/example.yml` and avoids filename collisions between selected subfolders.

## Conversion from the CLI

Convert only Windows rules:

```bash
python split_sigma_rules.py \
  --source /path/to/sigma/rules/windows \
  --output ./sigma-windows \
  --bundle-size 500
```

Select several folders and add your own tags:

```bash
python split_sigma_rules.py \
  --source /path/to/sigma/rules/windows/image_load \
  --source /path/to/sigma/rules/windows/process_creation \
  --source /path/to/sigma/rules-emerging-threats \
  --output ./sigma-separated \
  --tag 'custom:environment=production' \
  --tag 'custom:owner=security-team'
```

Use `--classify-only` to create classified copies, the manifest, duplicate-ID CSV, and summary without calling sigma-cli. The output folder must be new or empty and must not overlap a selected source. Existing output is never deleted or overwritten.

### Pipelines

| Sigma product | Pipeline |
| --- | --- |
| `windows` | `ecs_windows` |
| `macos` | `ecs_macos_esf` |
| `kubernetes` | `ecs_kubernetes` |
| `zeek` | `ecs_zeek_beats` |

Other products are sent to manual review during conversion. Pipeline selection comes from the rule's `logsource`, not its folder name. The tool does not use the Windows pipeline for Linux.

### Output and tags

| Output | Purpose |
| --- | --- |
| `classified/<collection>/` | Original YAML copies grouped by log source |
| `ndjson/<collection>/` | Validated detailed output |
| `bundles/` | Import bundles grouped by collection and product |
| `logs/` | Conversion logs and API import reports |
| `manual-review/` | Unsupported sources and duplicate-ID details |
| `manifest.csv` | Per-rule status, tags, output file, and bundle file |
| `summary.json` | Counts by collection, product, group, and status |

All exported rules are Disabled. Bundles contain at most 500 rules by default, configurable with `--bundle-size`. Collections and products are not mixed in a bundle.

Original Sigma and backend tags are retained, followed by these automatic tags and your extra tags:

```text
custom:managed-by=sigma-splitter
custom:source=<collection>
custom:product=<product>
custom:category=<category>
custom:pipeline=<pipeline>
custom:service=<service>
```

The service tag is omitted when the service is unspecified. Duplicate tags are removed while preserving their first occurrence. In the manifest, tag columns contain JSON arrays inside CSV cells; use a CSV parser rather than splitting lines on commas.

All occurrences of a duplicate source ID are excluded from conversion and listed in `manual-review/duplicate-rule-ids.csv`. No preferred copy is chosen. Output rules must match a source rule uniquely and have unique output IDs.

| Manifest status | Meaning |
| --- | --- |
| `converted` | Matched and validated; exported Disabled |
| `skipped` | sigma-cli did not export the rule |
| `manual_review` | Unsupported pipeline or invalid YAML |
| `duplicate_rule_id` | All source copies with this ID were excluded |
| `conversion_failed` | sigma-cli failed or produced no file |
| `validation_failed` | Converted output failed validation |
| `pending` | Valid source classified without conversion |

## Configure Kibana in the menu

1. Select `9` and enter the full Kibana URL, including `https://` or `http://`.
2. Enter a Space ID, or press Enter for the default Space.
3. Enter your CA certificate path if required, or press Enter for the system CA.
4. Select `12`, then choose an encoded API key or username/password.
5. Select `10` to test connectivity and read access to Detection Rules.
6. Select `11`, choose a bundle file or folder, review the target and count, and confirm the import.

For a domain behind a reverse proxy, use the URL you open in your browser, such as `https://kibana.example.org` or `https://security.example.org/kibana`. Do not append `:5601` unless the proxy actually exposes that port. The URL must not contain embedded credentials, query parameters, or a fragment.

API keys and passwords are entered with hidden input. Secret input requires an interactive terminal; the tool refuses an echo fallback. Switching authentication methods clears the inactive method so an old API key does not override a new username/password.

The menu changes environment variables for its own session. It does not save credentials to disk or change your parent shell. Kibana credentials are not passed to the Sigma conversion subprocess. Restarting the menu requires entering credentials again unless they were already supplied by your shell environment.

### Environment variables

| Variable | Purpose |
| --- | --- |
| `KIBANA_URL` | Full Kibana base URL |
| `KIBANA_SPACE` | Space ID; empty or `default` selects the default Space |
| `KIBANA_CA_CERT` | Optional CA certificate path |
| `KIBANA_API_KEY` | Encoded API key without the `ApiKey` prefix |
| `KIBANA_USERNAME` | Basic authentication username |
| `KIBANA_PASSWORD` | Basic authentication password |
| `SIGMA_LANGUAGE` | `en` or `vi` |

An API key takes precedence when both methods are supplied externally. The project does not load or write `.env` files.

## Import from the CLI

Set credentials in your current terminal or use the menu. API credentials configured inside the menu do not persist after the menu exits.

Example using Bash without placing the key in shell history:

```bash
export KIBANA_URL='https://kibana.example.org'
read -r -s -p 'Encoded Kibana API key: ' KIBANA_API_KEY
printf '\n'
export KIBANA_API_KEY
```

Check the connection:

```bash
python sigma_kibana_api.py --check
```

Validate local bundles and preview the target without network requests:

```bash
python sigma_kibana_api.py --bundles ./sigma-windows/bundles --dry-run
```

Import with an interactive confirmation:

```bash
python sigma_kibana_api.py --bundles ./sigma-windows/bundles
```

Or import one file:

```bash
python sigma_kibana_api.py \
  --file ./sigma-windows/bundles/sigma-core_windows_part-001.ndjson
```

`--url`, `--space`, `--ca-cert`, and `--language` override their environment defaults. `--timeout` defaults to 30 seconds. `--yes` explicitly confirms a non-interactive import. `--report` selects a new report file; existing reports are not overwritten.

### Import behavior

All selected files are validated before the first upload. Every rule must have `enabled: false` and a nonempty string `rule_id`; duplicate IDs across the selected files are rejected. Empty files and invalid NDJSON are rejected. Directory selection reads only `.ndjson` files directly inside that directory.

The importer sends multipart field `file` to:

```text
POST /api/detection_engine/rules/_import?overwrite=false
POST /s/<space_id>/api/detection_engine/rules/_import?overwrite=false
```

TLS certificate verification remains enabled. HTTP redirects are blocked, including redirects to login pages. Use the final Kibana URL and the correct CA certificate.

HTTP 200 alone is not treated as success. The importer checks success flags, counts, and rule/exception/connector errors. Import reports are written under `logs/` beside a selected bundles folder, or inside the selected file's parent folder when importing one file.

| Import status | Meaning |
| --- | --- |
| `imported` | The API confirmed all rules in that file |
| `failed` | The API returned an error or an incomplete result |
| `unknown` | No reliable confirmation, such as timeout, interruption, HTTP 5xx, or malformed response |
| `not_attempted` | The file was not sent because the batch stopped earlier |

The batch stops at its first unsuccessful file and never automatically retries a POST. It does not roll back rules already imported. For an unknown or partial result, check Kibana before trying again. When some rules already exist, create a reviewed bundle containing only the missing rules rather than resending every rule with overwrite enabled.

API key permissions affect the execution permissions of imported rules. The read-only connection test does not prove import permission. Imported payloads are Disabled, but the importer does not read back each rule after import. Confirm Disabled status, queries, index patterns, and telemetry in Kibana before enabling any rule.

## Testing

```bash
python3 -m py_compile *.py tests/*.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

The test suite covers classification, conversion orchestration, multiple source folders, duplicate IDs, tags, bundles, output protection, both languages, credential switching and hidden input, multipart uploads, HTTP/API errors, interruption, and redacted reports.

Conversion tests use a fake sigma executable. API tests use a local HTTP server that simulates Kibana. These tests do not establish compatibility with a live Kibana deployment or with the full Sigma rule corpus. The original deployment target was Elastic 8.9.0; verify it in your own pilot environment before importing production rules.

## Repository contents

```text
sigma-splitter/
├── README.md
├── requirements.txt
├── .gitignore
├── sigma_rules_menu.py
├── split_sigma_rules.py
├── sigma_kibana_api.py
├── ui_text.py
└── tests/
```

The ZIP contains the project files, including tests, without Git history, wiki files, generated rule output, credentials, virtual environments, or older archives. Tests are kept under `tests/` so future changes can be verified without cluttering the main folder.

To initialize your own Git repository after extracting it:

```bash
git init -b main
git add .
git commit -m "Initial Sigma Splitter project"
```

Review staged files before publishing. `.gitignore` excludes common credential files, downloaded rule collections, caches, and generated results.

## References

- [Sigma CLI guide](https://sigmahq.io/docs/guide/getting-started.html)
- [SigmaHQ Elasticsearch backend](https://github.com/SigmaHQ/pySigma-backend-elasticsearch)
- [Kibana v8: import detection rules](https://www.elastic.co/docs/api/doc/kibana/v8/operation/operation-importrules)
- [Kibana v8: find detection rules](https://www.elastic.co/docs/api/doc/kibana/v8/operation/operation-findrules)
