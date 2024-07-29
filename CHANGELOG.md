# Changelog

## Unreleased

## Fixed

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