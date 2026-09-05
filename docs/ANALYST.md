# TorBot Analyst

TorBot Analyst turns a versioned crawl result into a local investigation
bundle. It records stable evidence IDs and content hashes, maps page and
contact relationships, and requires every supported finding to reference
captured evidence.

## Five-minute quick start

Create a deterministic report without an AI provider:

```sh
torbot analyze tests/fixtures/analyst-safe-crawl.json \
  --provider none \
  --keyword example \
  --output investigation/
```

The output contains:

- `report.md` with supported, conflicted, and unsupported findings
- `evidence.jsonl` with captured URLs, excerpts, timestamps, and hashes
- `graph.json` with evidence-linked page and contact relationships
- `run.json` with reproducibility metadata and provider warnings

## Capture a crawl result

The existing tree and JSON outputs are unchanged. Save the new versioned
result explicitly:

```sh
torbot --url https://example.com \
  --disable-socks5 \
  --save result \
  --result-file crawl-result.json
```

The versioned result contains bounded visible text, not raw HTML, scripts,
styles, cookies, headers, credentials, or arbitrary exception messages.

## Local AI analysis

Ollama is the default provider and is contacted only on localhost:

```sh
torbot analyze crawl-result.json \
  --provider ollama \
  --model qwen3 \
  --output investigation/
```

If Ollama or the model is unavailable, TorBot still writes the deterministic
evidence bundle and records a warning in `run.json` and `report.md`.

## Remote OpenAI-compatible providers

Remote transmission is fail-closed. Both an explicit provider and
`--allow-remote` are required. The API key is read from `OPENAI_API_KEY` and is
never written to an output file. Email addresses and phone numbers are
redacted before remote transmission. Repeat `--redact-pattern` to add
case-specific regular expressions.

```sh
export OPENAI_API_KEY=your-key
torbot analyze crawl-result.json \
  --provider openai-compatible \
  --base-url https://api.openai.com/v1 \
  --model your-model \
  --allow-remote \
  --redact-pattern 'CASE-[0-9]+' \
  --output investigation/
```

Captured page text is untrusted data. Analyst exposes no tools to the model,
does not execute page instructions, discards unknown evidence references, and
never promotes an uncited model statement to `supported`.

## Schemas

Machine-readable schemas live in `schemas/crawl-result.v1.schema.json` and
`schemas/investigation-report.v1.schema.json`. Consumers must reject schema
versions they do not understand.
