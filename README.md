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
scripts/                   publisher tooling (lives with the catalog it builds)
```

Under each entity folder:

```
<type>/<id>/versions/<semver>/entity.json      immutable manifest of that version
<type>/<id>/versions/<semver>/package.tar.gz   its package (or index.db for a base)
<type>/<id>/latest/entity.json                 copy of the newest version's manifest
```

## What the platform verifies

Before anything is written to disk the platform checks the package against the
manifest: `package.sha256`, then every entry of `files` after unpacking, then
the archive itself (no symlinks, no path traversal, bounded size). A version is
immutable - once pushed, its folder never changes, so a client that pinned a
version can reproduce it byte for byte.

Credentials are never part of this repository. An MCP entity declares *which*
fields the user has to fill in (`preset.config.secret_env_fields`) and how the
server authenticates; the values live only in the user's own installation.

## Publishing a version

The publisher builds the package deterministically - same files, same bytes,
same sha256 on every machine - and refuses to overwrite a published version
with different content.

```bash
python scripts/marketplace_publish.py \
    --type skill --id my_skill --version 1.0.0 \
    --path ./build/my_skill --manifest ./build/my_skill/entity.json \
    --root . --sign-key ~/.sagaai/marketplace.pem
```

Steps the command performs: validate id/version, collect the folder, build
`package.tar.gz`, compute `files[]` and `package.sha256`, write the version
folder, refresh `latest/`, rebuild `index.json`, sign it.

### Signing keys

```bash
python scripts/marketplace_publish.py --root . --init-key --key-id sagaai-marketplace-2026
```

Writes the private half to `~/.sagaai/marketplace.pem` (mode 0600, never
committed) and the public half to `keys/<key_id>.pub`. The signature covers the
canonical JSON of the whole index: editing any entry invalidates it.

## Review flow

* `staging` - new and updated entities land here first.
* `main` - what the platform reads by default.
* tag `entity/<type>/<id>/<version>` - traces a published version to its commit.

## Licence

Each entity carries its own `license.spdx`. The catalog itself is documentation
and metadata; the packages it points at keep the licence stated in their
manifests.
