# container-registry

The `container-registry` crate implements a minimal "best effort" container registry suitable for plugging into [`axum`](https://docs.rs/axum/latest/axum/).

## Feature set and standard conformity

This crate has been cleaned up and factored out from the small PaaS [`rockslide`](https://github.com/mbr/rockslide), its feature set represents the requirements of said software. While it tries to follow the OCI [distribution](https://github.com/opencontainers/distribution-spec/blob/v1.0.1/spec.md) and [manifest](https://github.com/opencontainers/image-spec/blob/main/manifest.md) specifications, it was primarily written while reverse engineering real requests from [podman](https://podman.io/) and [Docker](https://www.docker.com/), thus while it may violate the specification some ways, it is certain to cover the basic use cases when using either tool.

The core functionality covered by this crate consists of

* authentication via HTTP basic auth,
* image uploading via `podman` or `docker`,
* image downloading via `podman` or `docker`, and
* storing container images on the local filesystem.

## Dependencies

An image registry cannot exist outside a web framework, unless it were to ship one itself. The framework underlying this crate is [`axum`](https://docs.rs/axum/latest/axum/) for now; wile support for other frameworks could be added with reasonable effort, no such work has been done at this time.

## Production readiness

The crate has not been thoroughly battle tested in contested production environments, or seen a deep review, so relying on it for mission critical deployments is probably a bad idea. At this point, it should make a reasonable drop-in replacement for other registries that are not publically accessible and can likely fulfill its role in system level tests.

## Use as a binary

`container-registry` includes a bare-bones installable binary that exposes most of its features from the command line. It is automatically built if the `bin` features is enabled:

```
cargo install container-registry --features bin
```
