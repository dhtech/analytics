# analytics

[![License](https://img.shields.io/badge/License-LGPL--3.0-blue.svg?style=for-the-badge)](https://github.com/dhtech/analytics/blob/master/LICENSE)

Gathers what the monitoring knows and serves it as small JSON documents
to [dhmap](https://github.com/dhtech/dhmap) (the hall map) and
[buildstatus](https://github.com/dhtech/buildstatus).

Every ten seconds it asks Prometheus and reads the network plan
(`/etc/ipplan.db`); the answers are served from memory.

| Address | What | From |
|---|---|---|
| `/event.hosts` | the site's hosts with their plan options | the plan |
| `/alerts.hosts`, `/mon.alerts` | alerts per host | `ALERTS` |
| `/ping.status` | seconds of the last minute without an answer to a ping (0 all answered, 60 none) | [pinger](https://github.com/dhtech/pinger): `icmp_rtt_seconds_count` |
| `/dhcp.status` | leases and size per network | [lease2db](https://github.com/dhtech/lease2db): `lease2db_scope_*` |
| `/syslog.status` | log size per sender | `syslog_log_bytes` |
| `/rancid.status` | saved configuration size per device | `rancid_config_bytes` |
| `/snmp.saves`, `/snmp.errors` | what the SNMP exporter gets | `snmp_exported_metrics_count`, `up` |
| `/switch.interfaces`, `/switch.vlans`, `/switch.model` | access switch ports, VLANs, model | the SNMP exporter's IF-MIB metrics |
| `/healthz` | 200 when everything was gathered lately | |

A source whose exporter is not there answers `{}`.

## Running

    pip install flask gunicorn
    ANALYTICS_PROMETHEUS=http://prometheus.example.net:9090 \
        gunicorn --workers 1 --threads 4 --bind 127.0.0.1:5000 analytics:application

One worker process: the gathering threads live in it. The pages expect
it under `/analytics/` on their own host - put a reverse proxy in front
that strips the prefix (nginx: `location /analytics/ { proxy_pass
http://127.0.0.1:5000/; }`).

| Environment | Default | |
|---|---|---|
| `ANALYTICS_PROMETHEUS` | `http://localhost:9090` | the Prometheus to ask |
| `ANALYTICS_IPPLAN` | `/etc/ipplan.db` | the plan database |
| `ANALYTICS_SITE` | `EVENT` | the site whose hosts `/event.hosts` lists |
| `ANALYTICS_CACHE_TIME` | `10` | seconds between two gatherings |
| `ANALYTICS_PING_INTERVAL` | `1` | seconds between two pings of a host - what `pingerd --interval` is run with |

For development: `python3 analytics.py` (port 5000 on localhost).

## Tests

    python3 -m pytest

They need no Prometheus and no Flask (the test of the routes is skipped
without Flask).
