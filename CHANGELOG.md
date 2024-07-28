# Changelog

## Unreleased

### Added

* Code factored out from <https://github.com/mbr/rockslide>, version 0.2.0.
* Added capability to use code as a library.

### Fixed

* The buffer size for uploads is now 1 megabyte, as intended, not 1 gigabyte.

### Removed

* Auth providers no longer contain dummy functionality that (falsely) hints at authorization checks (`has_access_to` has been removed).