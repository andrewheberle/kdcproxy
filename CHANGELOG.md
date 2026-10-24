# Changelog

## [1.7.0](https://github.com/andrewheberle/kdcproxy/compare/v1.6.0...v1.7.0) (2026-10-24)


### Features

* **logging:** log requests with a built-in access log that handles dropped connections ([#130](https://github.com/andrewheberle/kdcproxy/issues/130)) ([739cae0](https://github.com/andrewheberle/kdcproxy/commit/739cae03114fea900062c8e9ba20fa372f8075a7))

## [1.6.0](https://github.com/andrewheberle/kdcproxy/compare/v1.5.0...v1.6.0) (2026-10-23)


### Features

* **proxy:** relay password change requests to kpasswd servers ([#118](https://github.com/andrewheberle/kdcproxy/issues/118)) ([f54b04e](https://github.com/andrewheberle/kdcproxy/commit/f54b04e6770d8efef168b44cceab3c8ec1b66307))


### Bug Fixes

* log dropped connections as dropped rather than 200 OK ([#123](https://github.com/andrewheberle/kdcproxy/issues/123)) ([486b3af](https://github.com/andrewheberle/kdcproxy/commit/486b3afb1114b0e9ba3b2d088dae2f3089c76751))
* **metrics:** ensure successful request is counted properly ([#114](https://github.com/andrewheberle/kdcproxy/issues/114)) ([d23237a](https://github.com/andrewheberle/kdcproxy/commit/d23237a76b31bc6d7a195b7b11190fe334483f2d))
* **metrics:** label kdc_proxy_kerberos_requests_total with the protocol used ([#115](https://github.com/andrewheberle/kdcproxy/issues/115)) ([329dc0d](https://github.com/andrewheberle/kdcproxy/commit/329dc0dd03b085654a49c804faa42f60ab864228))
* **proxy:** drop the connection on a malformed Kerberos message ([#112](https://github.com/andrewheberle/kdcproxy/issues/112)) ([5913abe](https://github.com/andrewheberle/kdcproxy/commit/5913abe497a605c27ef95230ac05299c63a9e5fa))
* **proxy:** reject kerb-message with a short or mismatched length prefix ([#110](https://github.com/andrewheberle/kdcproxy/issues/110)) ([3a5f164](https://github.com/andrewheberle/kdcproxy/commit/3a5f16400a45447edc6e431b66685cb14bf89fc0)), closes [#96](https://github.com/andrewheberle/kdcproxy/issues/96)
* **proxy:** relay KRB-ERROR replies and validate KDC replies on both transports ([#113](https://github.com/andrewheberle/kdcproxy/issues/113)) ([18b4b4b](https://github.com/andrewheberle/kdcproxy/commit/18b4b4b57b4cecce80375ab828cff37a6633f038))
* **proxy:** route on target-domain and reject proxy messages without it ([#108](https://github.com/andrewheberle/kdcproxy/issues/108)) ([28e68fa](https://github.com/andrewheberle/kdcproxy/commit/28e68fa48236d2fd0016abc9cd62063cf05d8fcf)), closes [#99](https://github.com/andrewheberle/kdcproxy/issues/99) [#100](https://github.com/andrewheberle/kdcproxy/issues/100)
* serve TLS with the configured certificate ([#121](https://github.com/andrewheberle/kdcproxy/issues/121)) ([fd87887](https://github.com/andrewheberle/kdcproxy/commit/fd87887f92c20b58dc2ad33a32be16f13fb77306))

## [1.5.0](https://github.com/andrewheberle/kdcproxy/compare/v1.4.0...v1.5.0) (2026-10-23)


### Features

* bring config handling up to date, use new base image and overhaul dependencies ([a0c50f4](https://github.com/andrewheberle/kdcproxy/commit/a0c50f4f539d20f1e7d287e14cf6c3cdc5a43f30))


### Bug Fixes

* **deps:** update module github.com/prometheus/client_golang to v1.25.0 ([#86](https://github.com/andrewheberle/kdcproxy/issues/86)) ([b13f82a](https://github.com/andrewheberle/kdcproxy/commit/b13f82a79f4281d5e03f17cafeda594ebfc9c8ad))
* **deps:** update module golang.org/x/time to v0.16.0 ([#83](https://github.com/andrewheberle/kdcproxy/issues/83)) ([9c9fc9a](https://github.com/andrewheberle/kdcproxy/commit/9c9fc9a2d8edbc3defb28ee5b7e515bd7a264d1a))
