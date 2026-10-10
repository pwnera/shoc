# Changelog

## [0.1.0](https://github.com/pwnera/shoc/compare/v0.0.1...v0.1.0) (2026-10-10)


### Features

* **agents:** the Hunter wakes for each backlog item and closes in code what no source can show (DET-8, AGT-3, D159) ([7e35fd9](https://github.com/pwnera/shoc/commit/7e35fd9cc45aa5c41a6f1133cf81a3be6953a4e8))
* **agents:** wake agents on the events that concern them (AGT-1, AGT-3, DET-3, ING-2, RFC 0034, D146) ([0db13b5](https://github.com/pwnera/shoc/commit/0db13b5b5f34710ef902bd9a5dbf7da852940afc))
* **cases:** a case closed without its containment waits for a person (RSP-3, D152) ([b3eb413](https://github.com/pwnera/shoc/commit/b3eb413a9b7d7428be325351f33c94ed8da9c916))
* **console:** Coverage is a Detection tab, and /coverage redirects to it ([e820146](https://github.com/pwnera/shoc/commit/e820146563205356d71b0b300a032762e7cf00fd))
* **console:** every list table sorts from its column heads ([c9dd1da](https://github.com/pwnera/shoc/commit/c9dd1dacfd191c4cbc8e37e9ceb78e61c113c96e))
* **console:** indent raw records that arrive as JSON text, keeping 64-bit IDs exact ([a9a692a](https://github.com/pwnera/shoc/commit/a9a692aba934aedde779290f2142a88edfd91962))
* **content:** 86 rules and 4 hunt packs from public rule sets, with their upstreams credited in NOTICE (DET-2, ING-3, D156) ([1e9915e](https://github.com/pwnera/shoc/commit/1e9915e6ee683732c7c4bcda60ac5e1f2e5b4737))
* **deploy:** build the image with a warehouse extra and pass Databricks settings through Compose (STO-3, D131) ([2ef860c](https://github.com/pwnera/shoc/commit/2ef860c6f77e0a61edb8c8163e1b3fdf4925385e))
* **detect:** Stripe's security actions and a payout to a new destination fire, and the payouts read at install never do (ING-1, DET-1, DET-2, D157) ([f669772](https://github.com/pwnera/shoc/commit/f6697727680c95d594012d182464f6a568101875))
* **ingest:** a poll starts at the newest event read and waits out the vendor's documented lag (ING-1, ING-3, STO-3, D150, D154) ([09fff1d](https://github.com/pwnera/shoc/commit/09fff1dc68fa54504c3d53dc553e2cc20c37173d))
* **intel:** gate the content pipeline on what the tenant can act on, page an uncontained malicious case, and label sources by licence (DET-2, DET-4, DET-7, DET-8, AGT-3, AGT-13, AGT-14, RSP-4, ING-1, D137-D144) ([7e168d8](https://github.com/pwnera/shoc/commit/7e168d85561ba5d9faaa2153b3b9a563a7d02c92))
* shoc 0.0.1, the headless agentic SOC kernel ([690f534](https://github.com/pwnera/shoc/commit/690f5346a2d45b5ae07c420267c8194e4ae12b69))
* **worker:** one 15-minute cycle on every backend (DET-3, ING-1, D71, D151, D153) ([eb3f237](https://github.com/pwnera/shoc/commit/eb3f2373df998173e252d22f25e6c80ca5963059))


### Bug fixes

* **agents:** Sentinel no longer defers a finding (AGT-13, D145) ([74facc3](https://github.com/pwnera/shoc/commit/74facc37200db991c45736e0d3774115d067e001))
* **contract:** add the hunt.item event to the v1 snapshot (DET-8) ([33535e2](https://github.com/pwnera/shoc/commit/33535e2673f19b1a05f131496385e488c7a301ff))
* **detect:** read the event store only where a load can have changed something (DET-3, DET-4, DET-8, D149) ([03fdcc7](https://github.com/pwnera/shoc/commit/03fdcc71f2ecd7c950fbf1f094e79bab4f5b0d5d))
* **ingest:** a row the last poll already stored never reaches the store (ING-1, ING-3, STO-3, D71, D150) ([082069d](https://github.com/pwnera/shoc/commit/082069d3b2df09cd56a3b2c64f149b0c91c2a89b))
* **ingest:** GitLab audit events page by keyset and follow the next link as given (ING-1, D70, D155, D158) ([477f5f1](https://github.com/pwnera/shoc/commit/477f5f1503f3e117db4a173d7ffa24e0ef3cbe12))
* **ingest:** GitLab group mode reads every group and project below the group (ING-1, D70, D155) ([2bc7697](https://github.com/pwnera/shoc/commit/2bc769703bcbeb8bad0fa22ccbd19077053e54ed))
* **ingest:** the Stripe key asks for read on charges and early fraud warnings, unverified (ING-1) ([6588d1f](https://github.com/pwnera/shoc/commit/6588d1f6d641fb1f74e95631ce401090aceccde2))
* **ops:** source quality charges no actor gap to vendor automation and no lateness to a first backfill (OPS-1) ([9c1cd84](https://github.com/pwnera/shoc/commit/9c1cd84f54936ed3a65e111edfdb5685706312b6))
* **store:** read Databricks timestamps as UTC and quote the qualified events table for SQLGlot (STO-3) ([4d3c4f8](https://github.com/pwnera/shoc/commit/4d3c4f8eaddaa3776fa1934e924c11db2c84e6c2))
* **worker:** a source polls a warehouse once a cycle whenever it was configured (ING-1, DET-3, STO-3, D71, D151) ([74d8e11](https://github.com/pwnera/shoc/commit/74d8e110f1f54e8295d98a61652ead2b9987a5a1))
* **worker:** a sync wakes detection instead of running it, and the queue cannot outgrow the worker (DET-3, D71, RFC 0034, D147) ([b979be8](https://github.com/pwnera/shoc/commit/b979be86986d6e4381ad3e4ce01c0de570a3ad2a))
* **worker:** start without the event store, and give a Databricks statement a deadline (DET-3, STO-3, D148) ([7dbbd8c](https://github.com/pwnera/shoc/commit/7dbbd8c113cdecf579a5b5bd06dfe15f4c20701b))


### Performance

* **store:** a load is read once, and status reads stay in Postgres (DET-3, OPS-1, STO-1, D160-D163) ([7f6210b](https://github.com/pwnera/shoc/commit/7f6210bfdb566ab1390f0c6e7a29ed1a47637f41))


### Documentation

* confirm Apache 2.0 for the kernel (D12) ([4080017](https://github.com/pwnera/shoc/commit/4080017466bd9fb11c12f0150b6d7e0e6c4afff8))
