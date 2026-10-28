# SagaAI Marketplace Catalog

The catalog the SagaAI platform reads when you open the **Marketplace** section.
It is a plain folder tree served over raw.githubusercontent.com - no server, no
database, no build step at read time.

```
index.json                 the showcase: one summary per entity (generated, signed)
index.json.sig             Ed25519 signature over the canonical index JSON
keys/<key_id>.pub          trust anchor shipped with the platform
schema/*.json              JSON Schema of every file this repository holds
agents/<id>/               agent entities: an employee (agent_kind=orchestrator)
                           or a helper profile (agent_kind=assistant)
skills/<id>/               skill entities
rag/<id>/                  RAG bases
mcp/<id>/                  MCP server presets
bundles/<bundle_id>.json   curated sets of exact versions
scripts/publish.py         publisher tooling (lives with the catalog it builds)
```

Under each entity folder:

```
<type>/<id>/<semver>/entity.json       immutable manifest of that version
<type>/<id>/<semver>/package.tar.gz    its package (or index.db for a base)
<type>/<id>/latest/entity.json         copy of the newest version manifest
```

The version sits directly under the entity id, next to `latest/` - that is the
layout the platform resolves. There is no intermediate `versions/` folder.

## What the platform verifies

Before anything is written to disk the platform checks the package against the
manifest: `package.sha256`, then every entry of `files` after unpacking, then
the archive itself (no symlinks, no path traversal, bounded size). `index.json`
is rebuilt from the `latest/` pointers, so an entity without one never reaches
the showcase.

Credentials are never part of this repository. An MCP entity declares *which*
fields the user has to fill in (`preset.config.secret_env_fields`) and how the
server authenticates; the values live only in the user's own installation.

## What the manifest requires

Every manifest carries `schema`, `type`, `id`, `version`, `name`, `description`
and `license`. The package blocks are conditional, because not every entity
ships one:

* `skill` and `agent` - `files` and `package` are required.
* `rag` - always carries `distribution`. A base served as a prebuilt index
  declares `index_url`, `index_sha256` and `index_schema` instead of a package;
  the `sources_only` and `sources_plus_index` modes still ship `files` and
  `package`.
* `mcp` - a preset, not a package: the whole entity is the `preset` block, and
  the publisher drops `files` and `package` even when a draft carries them.

## Publishing a version

The publisher builds the package deterministically - same files, same bytes,
same sha256 on every machine - and refuses to overwrite a published version
with different content.

```
python scripts/publish.py --type skill --id my_skill --version 1.0.0 --path ./build/my_skill --manifest ./build/my_skill/entity.json --root . --sign-key ~/.sagaai/marketplace.pem
```

Steps the command performs: validate id and version, collect the folder, build
`package.tar.gz`, compute `files` and `package.sha256`, write the version
folder, refresh `latest/`, rebuild `index.json`, sign it.

A base whose index is a separate file is published from Python with
`extra_files` and the key `index.db`: the CLI writes `package.tar.gz` only.

### Signing keys

```
python scripts/publish.py --root . --init-key --key-id sagaai-marketplace-2026
```

Writes the private half to `~/.sagaai/marketplace.pem` (mode 0600, never
committed) and the public half to `keys/<key_id>.pub`. The signature covers the
canonical JSON of the whole index: editing any entry invalidates it.

Check a published catalog without changing it:

```
python scripts/publish.py --root . --verify-only
```

## Version immutability

A version folder is written once and never changes afterwards. Publishing the
same version with the same content is a no-op; with different content the
publisher refuses with `version_exists`. A correction is a new version - that is
what lets a client which pinned a version reproduce it byte for byte.

## Branch and tags

`main` is the only branch and what the platform reads by default. Publishing
goes straight to `main`: the guarantee is the immutability above, not a staging
branch. The repository carries no tags and no releases - packages are served
from this tree, and `package.url` is a path relative to the catalog root.

## Licence

Each entity carries its own `license.spdx`. The catalog itself is documentation
and metadata; the packages it points at keep the licence stated in their
manifests.
