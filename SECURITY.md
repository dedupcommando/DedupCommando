# Security Policy

DedupCommando deletes and relinks real files, so we treat security and **data-safety** bugs seriously and
ask that you report them **privately**.

## Supported versions

DedupCommando is in public beta. Security fixes target the latest **`0.9.0-beta.x`** release; older
pre-releases are not maintained.

## Reporting a vulnerability

**Please do not open a public issue for a vulnerability.** Use one of:

- **GitHub private vulnerability reporting** — the repository's *Security → "Report a vulnerability"* form
  (preferred, when enabled).
- **Email:** **dedupcommando@dequzzy.io** — the project's contact address.

> A dedicated `security@` mailbox may be added later (optional owner follow-up); until then, use the address
> above for security reports.

Please include: affected version, environment (kernel, ZFS version, filesystem), reproduction steps, and the
impact — especially anything that could cause **data loss** or bypass the snapshot / quarantine / content-
revalidation safeguards.

## In scope (high interest)

- **Data-loss paths:** deleting or relinking without a snapshot, bypassing quarantine, or skipping content
  revalidation before a destructive action.
- **TOCTOU / race conditions** on the write path.
- **Path-handling / privilege issues:** symlink traversal, cross-dataset moves, quarantine escape.

Out of scope: attacks that presuppose an already-compromised root account with write access to the data, and
non-Linux environments (unsupported).

## Disclosure process

We aim to acknowledge a report within a few days and to agree a fix and disclosure timeline with you. Please
allow reasonable time for a fix before public disclosure. We credit reporters unless you prefer to remain
anonymous.
