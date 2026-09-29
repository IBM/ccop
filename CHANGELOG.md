# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [0.1.0] - 2026-09-29

### Added
- Initial release of `ccop`, a command-line tool for security-sensitive Kubernetes operations in Confidential Containers (CoCo) deployments
- `ccop exec`: wraps `kubectl exec` arguments in an HPKE Auth-mode envelope, binding the user's identity to the request and encrypting all stdin/stdout/stderr traffic end-to-end
- `ccop fetch`: retrieves the workload's public key certificate from Trustee (KBS)
- `ccop config`: manages the local ccop environment (`~/.ccop/`), caches pod artifacts from Trustee, and reports ccop status across running pods

[unreleased]: https://github.com/IBM/ccop/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/IBM/ccop/releases/tag/v0.1.0
