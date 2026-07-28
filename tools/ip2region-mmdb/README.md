# ip2region to PowerDNS MMDB

PowerDNS Authoritative's GeoIP backend cannot read ip2region `.xdb` files
directly. This tool converts the official ip2region IPv4 and IPv6 source data
into the minimal MaxMind DB structure used by the existing GoEdge PowerDNS
LUA records:

- `continent.code` for `continent("AS")`
- `country.iso_code` for `country("CN")`
- `subdivisions[0].iso_code` for `region("GD")`

Only routing fields are written. City and ISP data are intentionally omitted
because the authoritative DNS routing logic does not read them.

The ip2region source files are the canonical input used to build
`ip2region_v4.xdb` and `ip2region_v6.xdb`. They are available from
`lionsoul2014/ip2region` under `data/ipv4_source.txt` and
`data/ipv6_source.txt`.

The existing city MMDB is used only to preserve continent codes and standard
ISO subdivision codes outside China. Chinese province names are mapped to the
same `BJ`, `GD`, `ZJ`, and other route codes already used by GoEdge.

The converter writes one IPv6-format MMDB containing both the IPv4 and IPv6
trees. IPv4 alias networks are disabled so native IPv6 ranges such as `6to4`
remain sourced from ip2region instead of being remapped to IPv4. Using one
dual-stack file also avoids PowerDNS trying an IPv4-only database during IPv6
queries.

```bash
go run . \
  -ipv4-source /path/to/ip2region/data/ipv4_source.txt \
  -ipv6-source /path/to/ip2region/data/ipv6_source.txt \
  -reference-mmdb /path/to/current-city.mmdb \
  -output /path/to/ip2region-goedge.mmdb
```

ip2region is dual-licensed under Apache-2.0 or MIT. No ip2region data files are
stored in this repository.
