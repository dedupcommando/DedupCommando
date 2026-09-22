# Release notes

One file per tag, named after it: the tag `v0.9.0-beta.4` reads
`docs/release-notes/v0.9.0-beta.4.md`. That file becomes the body of the GitHub release.

The notes are written by hand. Generating them from the log republishes every commit
subject since the previous tag, and a list of subjects cannot say what a release does
*not* establish — for a tool that deletes files, the part that matters most.

## Order of work

1. Set the new number in `VERSION`, in `Cargo.toml` and in the banner at the top of
   `README.md`; `cargo build` carries it into `Cargo.lock`.
2. Write `docs/release-notes/<tag>.md`.
3. Commit `VERSION`, `Cargo.toml`, `Cargo.lock`, `README.md` and the notes, and push.
4. Push the tag.

The release run refuses to start if the notes file is missing or empty, or if the tag,
`VERSION`, `Cargo.toml` and `Cargo.lock` name different versions, before anything is
compiled or signed. A tag pushed ahead of its notes or its version fails that check; fix
and push them, then delete the tag and push it again.

## What a release note covers

- What changes for someone already running the previous version.
- What it does not establish: known limits, paths the tests do not cover, anything left
  deliberately undone. This is the section a generated changelog cannot produce.
- Anything that needs action on upgrade.

Keep it short enough to be read before an upgrade, not after.
