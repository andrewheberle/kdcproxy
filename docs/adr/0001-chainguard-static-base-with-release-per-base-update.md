# Chainguard static base image, with a release per base update

The container image is built on `cgr.dev/chainguard/static`, pinned by digest. Renovate bumps that digest weekly as a `fix(deps)` commit and automerges it once `build` passes, so every base update ships as a new patch release through release-please. We never rebuild or re-push an existing version tag.

## Considered Options

- **distroless/base**: carries glibc and openssl, which the statically linked binary never uses, and has a noisier CVE report.
- **wolfi-base**: includes a shell and `apk`, so it is larger than what it would replace.
- **Docker Hardened Images (`dhi.io/static`)**: richer attestations (VEX, SLSA L3), but every pull needs a Docker login. That would mean a secret in CI and in Renovate, and a login for anyone building the Dockerfile.
- **Rebuilding existing tags in place on a schedule**: invisible to consumers who pin a version tag, orphans the cosign signatures and provenance attached to the old digest, and breaks immutable version tags. This is worth revisiting if consumers move to auto-updaters that follow digests, such as Flux with `digestReflectionPolicy: Always`.

## Consequences

Releases with no code changes are expected: their only changelog entry is the base image bump. Renovate uses `chore(deps)` for Dockerfile updates by default, which would never trigger a release, so the `fix` override in `renovate.json` is load-bearing.
