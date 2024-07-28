# container-registry

The `container-registry` crate implements a minimal "best effort" container registry based on [`axum`](https://docs.rs/axum/latest/axum/).

## Feature set and standard conformity

This crate has been cleaned up and factored out from the small PaaS [`rockslide`](https://github.com/mbr/rockslide), its feature set represents the requirements of said software. While it tries to follow the OCI [distribution](https://github.com/opencontainers/distribution-spec/blob/v1.0.1/spec.md) and [manifest](https://github.com/opencontainers/image-spec/blob/main/manifest.md) specifications, it was primarily written while reverse engineering real requests from [podman](https://podman.io/) and [Docker](https://www.docker.com/), thus while it may violate the specification some ways, it is certain to cover the basic usecases when using either tool.

The core functionality covered by this crate is:

* Authentication
* Image uploading via `podman` or `docker`
* Image downloading via `podman` or `docker`

## Dependencies

An image registry cannot exist outside a web framework (unless it were to ship one itself), the underlying framework for requests for this crate is [`axum`](https://docs.rs/axum/latest/axum/). While support for other frameworks could be added with reasonable effort, no such work has been done at this time.