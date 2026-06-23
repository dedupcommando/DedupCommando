# Verifying Releases

Each DedupCommando release (on GitHub Releases, for amd64 and arm64) ships with artifacts you can use to
verify the integrity and provenance of your download.

## Artifacts (per architecture)

- `dedcom-<version>-<triple>.tar.gz` — the binary plus `LICENSE`, `NOTICE`, `THIRD-PARTY-NOTICES`.
- `dedcom-<version>-<triple>.tar.gz.sha256` — SHA-256 checksum.
- `dedcom-<version>-<triple>.cdx.json` — CycloneDX SBOM (software bill of materials).
- `dedcom-<version>-<triple>.tar.gz.minisig` — minisign signature (see the note below).
- A SLSA build-provenance attestation (attached to the release via GitHub).

## 1. Checksum

```sh
sha256sum -c dedcom-<version>-<triple>.tar.gz.sha256   # expect: OK
```

## 2. Signature (minisign)

The project's minisign public key is:

```
RWS3JIpN+Qs0o91LEJ6RfrzeuJLDO3aiIcSS8YzJdayQnpKzPagqu9Z4
```

It is also published as [`minisign.pub`](../minisign.pub) in the repository root. Verify a release tarball
against it:

```sh
# with the key string directly
minisign -Vm dedcom-<version>-<triple>.tar.gz -P RWS3JIpN+Qs0o91LEJ6RfrzeuJLDO3aiIcSS8YzJdayQnpKzPagqu9Z4

# or with the published key file
minisign -Vm dedcom-<version>-<triple>.tar.gz -p minisign.pub
```

Expect: `Signature and comment signature verified`.

## 3. Build provenance (SLSA attestation)

Releases are built in GitHub Actions with a signed build-provenance attestation. Verify it with the GitHub
CLI:

```sh
gh attestation verify dedcom-<version>-<triple>.tar.gz --repo dedupcommando/DedupCommando
```

## 4. SBOM

The CycloneDX SBOM (`*.cdx.json`) lists the dependency tree and licenses, for auditing and supply-chain
tooling.
