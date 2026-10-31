# Image pipeline

Substrate: **Ubuntu 26.04 LTS** (decided 2026-10-30). The pipeline remasters the official desktop ISO; it does not rebuild Ubuntu. Implementation and status: [`image/README.md`](../image/README.md). Kernel and boot chain: [`KERNEL.md`](KERNEL.md).

```
eld .deb (packaging/deb) ──┐
repo payload ──────────────┼─> image/build-iso.sh ─> enterprise-linux-<ver>-<profile>-amd64.iso + .sha256
official 26.04 ISO ────────┘        (verified against Ubuntu SHA256SUMS)
```

CI ([`dist/ci/image.yml`](../dist/ci/image.yml)) builds a test ISO on pull requests and tags, installs it into a Secure Boot + TPM VM, and checks the first boot. Workflow files sit in `dist/ci/` and `ci/` because the automation token cannot push to `.github/workflows/`; copy them there to turn CI on.

Not done yet: signing the ISO checksums and UKIs (needs the key decision in KERNEL.md "Signing"), publishing to Releases, the `el-kernel-uki` package, reproducible build ids beyond the git revision in `BUILD.json`.
