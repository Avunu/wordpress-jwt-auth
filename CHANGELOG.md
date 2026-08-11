# Changelog

## [2.0.0](https://github.com/Avunu/wordpress-jwt-auth/compare/v1.2.1...v2.0.0) (2026-08-11)


### ⚠ BREAKING CHANGES

* **worker:** the AppConfig type export is replaced by ProviderConfig and WorkerConfig, signIdToken now takes a tenant, and the flow cookie is renamed to __Host-wp_auth_flow, which invalidates logins in flight across a deploy.

### Features

* **worker:** serve many sites from one issuer, with cross-site SSO ([5caacdd](https://github.com/Avunu/wordpress-jwt-auth/commit/5caacdd9434819f460e7a64667031a5a49622b37))


### Miscellaneous Chores

* bump php-stubs/woocommerce-stubs in the composer group ([#28](https://github.com/Avunu/wordpress-jwt-auth/issues/28)) ([f3ea605](https://github.com/Avunu/wordpress-jwt-auth/commit/f3ea60599751ffa9b818fa66830162b95e84bbab))
* bump the npm group in /worker with 2 updates ([#29](https://github.com/Avunu/wordpress-jwt-auth/issues/29)) ([cdbd113](https://github.com/Avunu/wordpress-jwt-auth/commit/cdbd113d339dcb2d0ba66d42c0c0a831b8bc8aa3))
* **main:** release jwt-auth-worker 1.0.0 ([a8d5eb2](https://github.com/Avunu/wordpress-jwt-auth/commit/a8d5eb27c3d40fcd71641aa71404d5400c8bb9cc))
* **main:** release jwt-auth-worker 1.0.0 ([1317d50](https://github.com/Avunu/wordpress-jwt-auth/commit/1317d506fa59e603b55ee8114f3ce9b5fd19da75))
* update deps ([9a13fbb](https://github.com/Avunu/wordpress-jwt-auth/commit/9a13fbbafb0376726fc451f5f6b45875f1645b8a))

## [1.2.1](https://github.com/Avunu/wordpress-jwt-auth/compare/v1.2.0...v1.2.1) (2026-08-10)


### Miscellaneous Chores

* bump @cloudflare/workers-types in /worker in the npm group ([#14](https://github.com/Avunu/wordpress-jwt-auth/issues/14)) ([0e87e06](https://github.com/Avunu/wordpress-jwt-auth/commit/0e87e06ba92aca279a102ae6fa42df699e1783c3))
* bump @cloudflare/workers-types in /worker in the npm group ([#16](https://github.com/Avunu/wordpress-jwt-auth/issues/16)) ([52e8fd0](https://github.com/Avunu/wordpress-jwt-auth/commit/52e8fd0efd3774996c91620d6daf642c1a5f702a))
* bump @cloudflare/workers-types in /worker in the npm group ([#20](https://github.com/Avunu/wordpress-jwt-auth/issues/20)) ([55f5a7a](https://github.com/Avunu/wordpress-jwt-auth/commit/55f5a7a4a350281fa5d045d9a0e500a1cba6d1bc))
* bump @cloudflare/workers-types in /worker in the npm group ([#22](https://github.com/Avunu/wordpress-jwt-auth/issues/22)) ([ba3ad30](https://github.com/Avunu/wordpress-jwt-auth/commit/ba3ad3028926f2405fe47aa0abe491af4d7b99f6))
* bump jose from 6.2.5 to 6.2.7 in /worker in the npm group ([#25](https://github.com/Avunu/wordpress-jwt-auth/issues/25)) ([6f773ce](https://github.com/Avunu/wordpress-jwt-auth/commit/6f773ce38b9da1bbd2225613adb49811478e209a))
* bump php-stubs/woocommerce-stubs in the composer group ([#13](https://github.com/Avunu/wordpress-jwt-auth/issues/13)) ([d66ece3](https://github.com/Avunu/wordpress-jwt-auth/commit/d66ece3aee9b2d88a2d66d5af3a2e1f9cf7da78f))
* bump the npm group in /worker with 2 updates ([#17](https://github.com/Avunu/wordpress-jwt-auth/issues/17)) ([46ed57f](https://github.com/Avunu/wordpress-jwt-auth/commit/46ed57f4e0a20afdf7625156a34121b5ccaf0196))
* bump the npm group in /worker with 3 updates ([#12](https://github.com/Avunu/wordpress-jwt-auth/issues/12)) ([c923b22](https://github.com/Avunu/wordpress-jwt-auth/commit/c923b22f10e1c6b86340f136f7005d912ff4c858))
* bump the npm group in /worker with 3 updates ([#19](https://github.com/Avunu/wordpress-jwt-auth/issues/19)) ([8d748ec](https://github.com/Avunu/wordpress-jwt-auth/commit/8d748ec8c83835b893cc6fde8879d7a3093996fb))
* bump the npm group in /worker with 3 updates ([#21](https://github.com/Avunu/wordpress-jwt-auth/issues/21)) ([19a6926](https://github.com/Avunu/wordpress-jwt-auth/commit/19a6926f8e60285c4dab61ef41a9db9432b8ea6a))
* bump the npm group in /worker with 3 updates ([#23](https://github.com/Avunu/wordpress-jwt-auth/issues/23)) ([0fb435e](https://github.com/Avunu/wordpress-jwt-auth/commit/0fb435ee0b426be0023ebf0ec04f9ad16813b91f))
* bump the npm group in /worker with 4 updates ([#15](https://github.com/Avunu/wordpress-jwt-auth/issues/15)) ([c46908f](https://github.com/Avunu/wordpress-jwt-auth/commit/c46908fe612b5a0953de10cd3cc7aa09831ea338))
* bump the npm group in /worker with 4 updates ([#24](https://github.com/Avunu/wordpress-jwt-auth/issues/24)) ([6f7e62c](https://github.com/Avunu/wordpress-jwt-auth/commit/6f7e62c457d70c63aded97e71e65bcdea535051f))
* bump the npm group in /worker with 4 updates ([#26](https://github.com/Avunu/wordpress-jwt-auth/issues/26)) ([89e5eb3](https://github.com/Avunu/wordpress-jwt-auth/commit/89e5eb321621a90c612875beab125d8705f0ed3a))
* bump the npm group in /worker with 6 updates ([#18](https://github.com/Avunu/wordpress-jwt-auth/issues/18)) ([0b5b955](https://github.com/Avunu/wordpress-jwt-auth/commit/0b5b955ad86c51bdafd3179e27f89e890103a4a1))
* update flake ([d78a02e](https://github.com/Avunu/wordpress-jwt-auth/commit/d78a02e195b32afe16a1b8a2caa46ef2e4103cd1))

## [1.2.0](https://github.com/Avunu/wordpress-jwt-auth/compare/v1.1.1...v1.2.0) (2026-07-14)


### Features

* **worker:** change email auth path ([b62dbb5](https://github.com/Avunu/wordpress-jwt-auth/commit/b62dbb548d0d4b343be8b2905e17be77108b7b15))


### Miscellaneous Chores

* bump actions/setup-node from 6 to 7 in the github-actions group ([#8](https://github.com/Avunu/wordpress-jwt-auth/issues/8)) ([9e944ca](https://github.com/Avunu/wordpress-jwt-auth/commit/9e944ca03023a4d46dd3f3ff9d4692072b7f4e62))
* bump the npm group in /worker with 3 updates ([#9](https://github.com/Avunu/wordpress-jwt-auth/issues/9)) ([a4ce669](https://github.com/Avunu/wordpress-jwt-auth/commit/a4ce669fdc056870dd4f804e7efef737e59250e4))
* **main:** release jwt-auth-worker 0.3.0 ([75a237f](https://github.com/Avunu/wordpress-jwt-auth/commit/75a237fa58c2c6afd9f682583c2262309bdcb328))
* **main:** release jwt-auth-worker 0.3.0 ([e897df5](https://github.com/Avunu/wordpress-jwt-auth/commit/e897df56154c2844c62723065d16661c77417557))

## [1.1.1](https://github.com/Avunu/wordpress-jwt-auth/compare/v1.1.0...v1.1.1) (2026-07-13)


### Bug Fixes

* ensure that log-out clears wordpress session ([8fc9fc4](https://github.com/Avunu/wordpress-jwt-auth/commit/8fc9fc4bbef44fa0c2f344a5232d0149d912740b))


### Miscellaneous Chores

* auto-merge dependabot PRs ([787ccac](https://github.com/Avunu/wordpress-jwt-auth/commit/787ccac266bf3608186278ef9a3b49ff16ac9cf4))
* bump php-stubs/woocommerce-stubs in the composer group ([#5](https://github.com/Avunu/wordpress-jwt-auth/issues/5)) ([624d395](https://github.com/Avunu/wordpress-jwt-auth/commit/624d395953a9b13a59d5911b29007ecad9ebaab2))
* bump the github-actions group with 2 updates ([ea9d970](https://github.com/Avunu/wordpress-jwt-auth/commit/ea9d970097111d49606edea7c906e1a2aed7a696))
* bump the github-actions group with 2 updates ([ac5783d](https://github.com/Avunu/wordpress-jwt-auth/commit/ac5783ddcc4b9b78ddfcc80af6b90c5a22a1eda5))
* mark worker release as prerelease to avoid conflicts with plugin-update-checker ([6eb1f0b](https://github.com/Avunu/wordpress-jwt-auth/commit/6eb1f0bd7cade1e194e36372ff8e6afc4ceef654))
* phpstan check in ci ([50ef1e5](https://github.com/Avunu/wordpress-jwt-auth/commit/50ef1e54e3272a4e8d915707429785dc98e229ed))
* update deps ([733acc8](https://github.com/Avunu/wordpress-jwt-auth/commit/733acc86fff970b9cb59cdfcab4be404d8570778))

## [1.1.0](https://github.com/Avunu/wordpress-jwt-auth/compare/v1.0.1...v1.1.0) (2026-07-11)


### Features

* cloudflare worker ([254c7d3](https://github.com/Avunu/wordpress-jwt-auth/commit/254c7d3e403f3b75a9f4fa98e30d2a7a75074d37))


### Miscellaneous Chores

* cloudflare types ([7501606](https://github.com/Avunu/wordpress-jwt-auth/commit/7501606ad9a5855a106e8a600f7d782d76550478))
* git-hooks ([da12bc4](https://github.com/Avunu/wordpress-jwt-auth/commit/da12bc48b619df93d1f414de4919cd9c8583f109))
* release please ([091754d](https://github.com/Avunu/wordpress-jwt-auth/commit/091754d4fe1ed1243ca600dae057fee5ec5985c1))

## [1.0.1](https://github.com/Avunu/wordpress-jwt-auth/compare/v1.0.0...v1.0.1) (2026-07-10)


### Miscellaneous Chores

* **deps:** bump firebase/php-jwt from 7.0.5 to 7.1.0 ([2b0b237](https://github.com/Avunu/wordpress-jwt-auth/commit/2b0b2373ebee8ba2d5b38de2f795a3353c3c0d5a))
* **deps:** bump firebase/php-jwt from 7.0.5 to 7.1.0 ([8b1421d](https://github.com/Avunu/wordpress-jwt-auth/commit/8b1421db7b9f7fa265a48bcb9f556888157092e8))
* release-please release ([4e52260](https://github.com/Avunu/wordpress-jwt-auth/commit/4e52260ff78f2f9bf637f510243f600a698da1b1))
* update flake ([cebd72a](https://github.com/Avunu/wordpress-jwt-auth/commit/cebd72a183d42e235e674b5b2ca105ecf4f36a0f))
