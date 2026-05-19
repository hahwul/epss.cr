+++
title = "Response"
description = "EPSS::Response — decoded envelope from one API call"
weight = 5
+++

`EPSS::Response` is what `EPSS::Client#fetch` returns. It carries the
FIRST API envelope's metadata along with the flattened
`Array(EPSS::Score)`.

## Fields

| Field | Type | Source |
| --- | --- | --- |
| `#status` | `String` | envelope `status` (e.g. `"OK"`) |
| `#status_code` | `Int32` | envelope `status-code` (e.g. `200`) |
| `#version` | `String` | envelope `version` |
| `#access` | `String` | envelope `access` |
| `#total` | `Int32` | total rows matching the query |
| `#offset` | `Int32` | server-reported start offset |
| `#limit` | `Int32` | server-reported page size |
| `#scores` | `Array(EPSS::Score)` | flattened score list |
| `#row_count` | `Int32` | server `data.size` *before* flattening |

## Predicates

### `#ok? : Bool`

`status == "OK"` and `status_code == 200`. Used internally and useful
for double-checking when callers wrap their own response handling.

### `#more? : Bool`

`offset + row_count < total`. Drives `Client#each_score` pagination.
Compares against `row_count` (not `scores.size`) so it stays correct
when `scope=time-series` inflates each row into ~30 daily entries.

## Enumerable

`Response` includes `Enumerable(Score)`, so iteration works directly:

```crystal
resp = client.fetch(query)
resp.each { |score| publish(score) }
resp.select { |s| s.epss > 0.5 }
```

## Parsing

### `Response.from_json(input : String | IO) : Response`

Decode a FIRST EPSS JSON payload. Raises:

- `EPSS::APIError` if the envelope reports an error
  (`status != "OK"` or `status-code != 200`);
- `EPSS::ParseError` if the JSON is missing required fields or has the
  wrong shape.

The `time-series` array nested inside each data row (when
`scope=time-series`) is expanded into additional `Score`s in the
returned `scores` list — each with the parent's `cve` copied over.
