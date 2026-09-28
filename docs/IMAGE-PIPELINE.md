# Image pipeline

Stub. CI → reproducible artifact on tag; checksums on Releases; signing when keys exist.

See `docs/ARCHITECTURE.md` §5.3. No ISO blobs in git.

## CI layout (later)

When the image seed exists, add `.github/workflows/` build-on-tag here. Until then this repo has no workflow files (GitHub OAuth tokens without `workflow` scope cannot push them).
