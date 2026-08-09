# Configuration examples

| File | What it is |
|---|---|
| [`../starling.example.toml`](../starling.example.toml) | **The one to copy.** What somebody running a server for their friends changes: the name, the port, how many people may join, the password, chat and audio limits |
| [`reference.toml`](reference.toml) | Every key that exists, with its default and a sentence on what it does. A reference sheet, not a starting point |
| [`advanced/`](advanced/) | The knobs you should not need, one file per subject |
| [`../deploy/starling.toml`](../deploy/starling.toml) | Not for editing: the file `docker-compose.yml` mounts into its containers |

## Where configuration comes from

The defaults are **compiled into the binary**, which is why `starling
--all-in-one` with no file at all is a working server. A file overlays them, and
environment variables overlay the file. No file is read unless you pass
`--config`.

Everything in `advanced/` is a valid configuration on its own and can be pulled
into yours:

```toml
include = ["examples/advanced/logging.toml", "examples/advanced/admin-api.toml"]
```

Paths are relative to the file naming them, a directory means every `*.toml`
directly inside it in name order, and the file naming them wins over what it
pulls in. A file may include files that include others; the same file being
reached twice is refused rather than merged twice.

| File | What it is for |
|---|---|
| [`advanced/logging.toml`](advanced/logging.toml) | Where the operator log goes, and metrics and traces |
| [`advanced/rate-limits.toml`](advanced/rate-limits.toml) | The gateway's buckets, queues and connection resume |
| [`advanced/admin-api.toml`](advanced/admin-api.toml) | The REST admin plane, its authentication and its audit log |
| [`advanced/services.toml`](advanced/services.toml) | Endpoints, tiers, routing and per-service databases |

## You are overlaying, not replacing

A configuration file names what it changes. Everything it is silent about keeps
the built-in value, so nothing below has to be restated to be kept, and
`--config` never silently disables a service by not mentioning it.

The one thing to know: a value replaces rather than merges, arrays included. A
`types` list is the whole list, and `[[instances]]` means *these* instances.

## Or use environment variables

Every key has one, so a Kubernetes `ConfigMap` needs no templating and
`docker compose` needs no mount. Uppercase the path, turn dots and dashes into
underscores, prefix `STARLING_`:

```
[services.text] endpoint  ->  STARLING_SERVICES_TEXT_ENDPOINT
```

They are applied after the files, so an environment variable wins.
