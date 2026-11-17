# Changelog

## [0.4.0](https://github.com/open-source-cloud/kong-jwt-keycloak/compare/kong-jwt-keycloak-v0.3.1...kong-jwt-keycloak-v0.4.0) (2026-11-17)


### Features

* add allowed_aud and allowed_typ checks ([#18](https://github.com/open-source-cloud/kong-jwt-keycloak/issues/18)) ([eb0ade8](https://github.com/open-source-cloud/kong-jwt-keycloak/commit/eb0ade808ddc9b7d596f0d920ee614153088a225)), closes [#14](https://github.com/open-source-cloud/kong-jwt-keycloak/issues/14)


### Bug Fixes

* escape control characters in logged rejection reasons ([#19](https://github.com/open-source-cloud/kong-jwt-keycloak/issues/19)) ([2167641](https://github.com/open-source-cloud/kong-jwt-keycloak/commit/2167641d821f19034c10a3cec7f8166b10c30097))
* stop returning validation details in 401 responses ([#17](https://github.com/open-source-cloud/kong-jwt-keycloak/issues/17)) ([90e87ab](https://github.com/open-source-cloud/kong-jwt-keycloak/commit/90e87ab96827d4fccfa414522530458a7f0fbe24)), closes [#13](https://github.com/open-source-cloud/kong-jwt-keycloak/issues/13)
* throttle JWKS refetches for unknown kids ([#16](https://github.com/open-source-cloud/kong-jwt-keycloak/issues/16)) ([d0290e2](https://github.com/open-source-cloud/kong-jwt-keycloak/commit/d0290e2d15579598c98fb75be15383854ed97ad8)), closes [#12](https://github.com/open-source-cloud/kong-jwt-keycloak/issues/12)


### Build System

* **deps:** bump actions/checkout from 4 to 7 ([#9](https://github.com/open-source-cloud/kong-jwt-keycloak/issues/9)) ([47d8327](https://github.com/open-source-cloud/kong-jwt-keycloak/commit/47d8327a9c0f638453e9df2194bda888ad1aacfa))
* **deps:** bump docker/login-action from 3 to 4 ([#6](https://github.com/open-source-cloud/kong-jwt-keycloak/issues/6)) ([7c419e7](https://github.com/open-source-cloud/kong-jwt-keycloak/commit/7c419e7f7b8d1db3ec6c0ebda8b9ee9445cae919))
* **deps:** bump docker/metadata-action from 5 to 6 ([#8](https://github.com/open-source-cloud/kong-jwt-keycloak/issues/8)) ([a37ea3b](https://github.com/open-source-cloud/kong-jwt-keycloak/commit/a37ea3ba58e5bea54d9d5a7d5ddc030fbde58185))
* **deps:** bump docker/setup-buildx-action from 3 to 4 ([#5](https://github.com/open-source-cloud/kong-jwt-keycloak/issues/5)) ([7d4b6cd](https://github.com/open-source-cloud/kong-jwt-keycloak/commit/7d4b6cd6aea56857237ee09bc92cfeac3414ef31))
* **deps:** bump golang from 1.26-alpine to 1.27-alpine ([#4](https://github.com/open-source-cloud/kong-jwt-keycloak/issues/4)) ([f6ebce9](https://github.com/open-source-cloud/kong-jwt-keycloak/commit/f6ebce98a328073fb0d72b43907f7b47d17ce663))
* **deps:** bump softprops/action-gh-release from 2 to 3 ([#7](https://github.com/open-source-cloud/kong-jwt-keycloak/issues/7)) ([5566c67](https://github.com/open-source-cloud/kong-jwt-keycloak/commit/5566c672e39d2f87c8d616a923e15308f6722679))

## [0.3.1](https://github.com/open-source-cloud/kong-jwt-keycloak/compare/kong-jwt-keycloak-v0.3.0...kong-jwt-keycloak-v0.3.1) (2026-10-18)


### Bug Fixes

* **ci:** publish the release image and document Kong 3.9 sidecar mode ([#10](https://github.com/open-source-cloud/kong-jwt-keycloak/issues/10)) ([fd69a4e](https://github.com/open-source-cloud/kong-jwt-keycloak/commit/fd69a4ea9f6f068071c6f6bd02a3ecd5e1e2a9ef))

## [0.3.0](https://github.com/open-source-cloud/kong-jwt-keycloak/compare/kong-jwt-keycloak-v0.2.0...kong-jwt-keycloak-v0.3.0) (2026-08-22)


### Features

* Kong plugin for Keycloak JWT validation ([0df4e66](https://github.com/open-source-cloud/kong-jwt-keycloak/commit/0df4e66744cdcd47c9edf53c708ad458bd461960))


### Bug Fixes

* **ci:** publish correct image tag in release notes ([178a0b1](https://github.com/open-source-cloud/kong-jwt-keycloak/commit/178a0b12df62a2334de57a79ef2d9631446c9227))


### Refactoring

* adopt cmd/internal/pkg project layout ([69d437e](https://github.com/open-source-cloud/kong-jwt-keycloak/commit/69d437eb177886b975acf30c6de8068ae9f8eca3))


### Build System

* **deps:** bump busybox from 1.37 to 1.38 ([#1](https://github.com/open-source-cloud/kong-jwt-keycloak/issues/1)) ([df574d2](https://github.com/open-source-cloud/kong-jwt-keycloak/commit/df574d20078750b33a08378c46e922215d796115))
* **deps:** bump golang from 1.25-alpine to 1.26-alpine ([#2](https://github.com/open-source-cloud/kong-jwt-keycloak/issues/2)) ([8773eea](https://github.com/open-source-cloud/kong-jwt-keycloak/commit/8773eea235bed5af24b4d1f1a410470fe9283393))


### CI

* add test, release and release-please workflows ([4e25bfa](https://github.com/open-source-cloud/kong-jwt-keycloak/commit/4e25bfa0d8ee4d8b96a9cf4efa4096b36cb1d215))
