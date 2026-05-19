+++
title = "API Reference"
description = "Public types and methods exposed by epss.cr"
sort_by = "weight"
+++

Reference documentation for every public type in epss.cr. Each page
lists the constructors, methods, and key invariants.

| Type | Purpose |
| --- | --- |
| [`EPSS::Score`](/api-reference/score/) | One daily EPSS measurement for a single CVE |
| [`EPSS::Band`](/api-reference/band/) | Qualitative bucket over score or percentile |
| [`EPSS::Client`](/api-reference/client/) | HTTP client for the FIRST EPSS REST API |
| [`EPSS::Query`](/api-reference/query/) | Typed query builder |
| [`EPSS::Response`](/api-reference/response/) | Decoded envelope from one API call |
| [`EPSS::CSV`](/api-reference/csv/) | Daily CSV-feed parser |
| [`EPSS::Error` and friends](/api-reference/errors/) | The error hierarchy |
