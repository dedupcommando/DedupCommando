# Release notes

One file per tag, named after it: the tag `v0.9.0-beta.4` reads
`docs/release-notes/v0.9.0-beta.4.md`. That file becomes the body of the GitHub release.

The notes are written by hand. Generating them from the log republishes every commit
subject since the previous tag, and a list of subjects cannot say what a release does
*not* establish — for a tool that deletes files, the part that matters most.

## Order of work

1. Write `docs/release-notes/<tag>.md`.
2. Commit and push it.
3. Push the tag.

The release run refuses to start if the file is missing or empty, before anything is
compiled or signed. A tag pushed ahead of its notes fails that check; write the notes,
push them, then delete the tag and push it again.

## What a release note covers

- What changes for someone already running the previous version.
- What it does not establish: known limits, paths the tests do not cover, anything left
  deliberately undone. This is the section a generated changelog cannot produce.
- Anything that needs action on upgrade.

Keep it short enough to be read before an upgrade, not after.
