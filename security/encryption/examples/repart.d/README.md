# Encryption at first boot (image pipeline note)

Goal from docs/ENCRYPTION.md section 2: every device is encrypted before first login.

Two ways to get there, both distro-agnostic as long as the initrd is
systemd-based (dracut on RHEL 9/10 and Ubuntu >= 25.10):

1. **systemd-repart at first boot** (preferred for image-based installs).
   Ship `50-root.conf` in `/usr/lib/repart.d/` (or the initrd) and let
   `systemd-repart.service` create the root partition with `Encrypt=tpm2`.
   It formats LUKS2 (systemd picks aes-xts-plain64 / 512-bit; check with
   `el-encryption-facts`) and enrolls the TPM2 of *this* machine, so no
   per-device secret is baked into the image.
   - Use `Encrypt=key-file+tpm2` with a one-time key file from the
     installer if you want to hand a credential to `el-recovery-escrow`
     right after first boot. Destroy that key file afterwards.
   - systemd-repart only *creates* encrypted partitions; it does not
     encrypt an existing filesystem in place.
2. **Installer (Anaconda / Subiquity / custom)** formats LUKS2 with a
   temporary passphrase, then a first-boot unit runs:

   ```
   el-luks-enroll --device /dev/disk/by-partlabel/root --mode tpm2+pin \
       --unlock-key-file /run/el/install.key --regenerate-initrd
   el-recovery-escrow escrow --device /dev/disk/by-partlabel/root \
       --unlock-key-file /run/el/install.key
   systemd-cryptenroll --wipe-slot=password /dev/disk/by-partlabel/root   # drop the temp passphrase
   ```

   Only wipe the temporary passphrase after escrow succeeded, so a
   recovery path always exists.

Not verified on hardware yet: TPM-less VMs, swtpm and real laptops still
need to be tested for both paths.
