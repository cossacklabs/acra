## 0.85.0 - 2020-04-02
### Added
- Support of RHEL >= 7
- Configurable build and install parameters in Makefile (see `make help`)
- Self-documented Makefile
- `go_install.sh` script
- Makefile `pkg` target with automatic detection of OS (use it instead of `rpm` and `deb`)
### Changed
- Build image use Debian 10 instead of Debian 9
- Application names in Docker image description got `CE` suffix
- Refined logic of automatic image tagging
### Removed
- Makefile targets `dist`, `temp_copy`
- `docker_push` target replaced with `docker-push`
- default argument `--db_host=postgres` from `acra-server` docker image, specifying it explicitly is more secure
- default argument `--acraserver_connection_host=acra-server` from `acra-connector` image
### Deprecated
- `docker` target in Makefile (will be removed in 0.87.0), use `docker-build` instead
- docker images `acra-authmanager` and `acra-keymaker` (will be removed in 0.87.0); all tools are now packaged into the `acra-tools` image
- Makefile targets `rpm` and `deb` are aliases for `pkg` and will be removed in future
