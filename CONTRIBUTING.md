# Contributing

Thanks for your interest in epss.cr.

## Local development

```sh
shards install
crystal spec                # 67+ examples
crystal tool format --check
```

Run an example end-to-end:

```sh
crystal run examples/json_io.cr   # offline
crystal run examples/basic.cr -- CVE-2022-27225   # hits api.first.org
```

The HTTP-touching code is fully driven through an injectable
`EPSS::Transport`; specs swap in a `StubTransport` (see
`spec/spec_helper.cr`) and never reach the network.

## Submitting changes

1. Fork the repository and create a branch.
2. Add or update specs under `spec/` for any code change.
3. Make sure `crystal spec` and `crystal tool format --check` pass — CI runs both.
4. Open a pull request describing the change and linking to the relevant
   FIRST EPSS documentation if applicable.

## Reporting issues

Please open an issue with:

- The CVE (or sample CSV row / API payload) that triggers the problem.
- The expected EPSS score / percentile (with a link to the FIRST EPSS
  query that produced it: `https://api.first.org/data/v1/epss?cve=…`).
- The score / band epss.cr returned.

## Spec compliance

epss.cr aims to match the official FIRST EPSS API and daily-feed format:

- [EPSS overview](https://www.first.org/epss/)
- [API documentation](https://www.first.org/epss/api)
- [Daily CSV feed](https://epss.cyentia.com/) (model version + score date in
  the `#` header line, `cve,epss,percentile` columns)

Bug reports referencing a specific section of these documents land fastest.
