# Changelog

## Unreleased

### Added

* `AuthProvider`s can now grant fine grained permissions based on location or blob digest.
* An `Anonymous<A>` auth provider is now available that allows granting access to clients without credentials.
* Additional functionality for using the registry in unit tests has been added in the form of the
  `test_support` module.

### Changed

* The `AuthProvider` API has changed to also include permissions.
* `Registry::new` has been replaced by a builder pattern, see `Registry::builder`.

### Removed

* The `AuthProvider` implementation of `bool` has been removed, use `Permissions::ReadWrite` as a replacement.

## [0.1.2] - 2024-07-29

### Fixed

* Manifest upload now also returns the correct location error.

## [0.1.1] - 2024-07-29

### Fixed

* Upload finalization now returns the required `Location` header, making it work with the [`oci-distribution`](https://docs.rs/oci-distribution) crate.

## [0.1.0] - 2024-07-29

### Added

* Code factored out from <https://github.com/mbr/rockslide>, version 0.2.0.
* Added capability to use code as a library.
* A small binary to run a registry from the command line is included as well.

### Fixed

* The buffer size for uploads is now 1 megabyte, as intended, not 1 gigabyte.

### Removed

* Auth providers no longer contain dummy functionality that (falsely) hints at authorization checks (`has_access_to` has been removed).