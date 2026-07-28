# Support

Use the current GitHub Release or a source build from the current `main`
branch. Supported platforms and prerequisites are listed in the
[installation guide](docs/getting-started/installation.md).

Before opening an issue:

1. Read the [README](README.en.md), installation guide, and command `--help`.
2. Search existing issues.
3. Retry with the latest supported release when practical.

For a normal bug, use the
[bug report form](https://github.com/ReiSuzunami/sloosh/issues/new?template=bug_report.yml)
and include:

- `sloosh --version` or the exact commit;
- OS, architecture, and installation channel;
- minimal reproduction steps, expected behavior, and actual behavior;
- relevant `diagnostic_code` values and redacted errors or logs. A
  `suppressed=N` field means equivalent background failures were aggregated
  during the warning window, not lost from the current command result.

Never publish passwords, private keys, vault data, lease tokens, or sensitive
audit/spool contents. Review `RUST_LOG=debug` and `daemon.log` output before
sharing: private paths, host topology, and command metadata may still be
operationally sensitive. Report vulnerabilities only through
[SECURITY.md](SECURITY.md). Feature requests are welcome but do not imply a
commitment or response deadline. This is a maintainer-supported project without
a guaranteed support SLA.
