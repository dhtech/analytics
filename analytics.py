# Copyright 2018 dhtech
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file
"""analytics: what the monitoring knows, as small JSON documents.

dhmap (the hall map) and buildstatus ask these addresses; each answer is
gathered in the background every CACHE_TIME seconds from Prometheus and
the network plan, and served from memory.

Where things are is taken from the environment:

  ANALYTICS_PROMETHEUS   the Prometheus to ask
                         (default http://localhost:9090)
  ANALYTICS_IPPLAN       the plan database (default /etc/ipplan.db)
  ANALYTICS_SITE         the site whose hosts /event.hosts lists
                         (default EVENT)
  ANALYTICS_CACHE_TIME   seconds between two gatherings (default 10)
  ANALYTICS_PING_INTERVAL  seconds between two pings of a host, as the
                         ping collectors (pingerd --interval) are run
                         (default 1)

Run it under a WSGI server with ONE worker process (the gathering
threads live in it):

  gunicorn --workers 1 --threads 4 --bind 127.0.0.1:5000 analytics:application

or, for development, `python3 analytics.py`.
"""
import collections
import concurrent.futures
import flask
import functools
import json
import os
import sqlite3
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request


DB_FILE = os.environ.get('ANALYTICS_IPPLAN', '/etc/ipplan.db')
PROMETHEUS = os.environ.get('ANALYTICS_PROMETHEUS',
                            'http://localhost:9090').rstrip('/')
SITE = os.environ.get('ANALYTICS_SITE', 'EVENT').upper()
CACHE_TIME = float(os.environ.get('ANALYTICS_CACHE_TIME', '10'))
PING_INTERVAL = float(os.environ.get('ANALYTICS_PING_INTERVAL', '1'))
# seconds one question to Prometheus may take
TIMEOUT = 10
# before a source has been gathered once: an empty document, so that a
# page asking early reads "nothing yet" and not something it cannot parse
EMPTY = '{}'


class DataSource(object):
  def __init__(self, data, func):
    self.data = data
    self.func = func
    # when it was last gathered without an error (0: never)
    self.updated = 0


app = flask.Flask(__name__)
data_sources = {}


def analytics(t):
  def handler(func):
    data_sources[t] = DataSource(EMPTY, func)
    @app.route(t)
    @functools.wraps(func)
    def wrapper():
      return flask.Response(data_sources[t].data,
                            mimetype='application/json')
    return wrapper
  return handler


def prometheus(query):
  url = '{host}/api/v1/query?query={query}&time={time}'
  o = urllib.request.urlopen(url.format(
    query=urllib.parse.quote(query), time=int(time.time()), host=PROMETHEUS),
    timeout=TIMEOUT)
  return o.read()


def series(query):
  """The time series Prometheus answers QUERY with."""
  return json.loads(prometheus(query))['data']['result']


def hostname(labels):
  """The host a series is about: its "host" label, else its instance,
  without a port."""
  host = labels.get('host') or labels.get('instance') or ''
  return host.split(':')[0]


@analytics('/event.hosts')
def event_hosts():
  conn = sqlite3.connect('file:%s?mode=ro' % DB_FILE, uri=True)
  try:
    c = conn.cursor()
    c.execute('SELECT h.node_id, h.name, n.name '
              'FROM host h, network n WHERE n.node_id = h.network_id')

    nodes = {}
    for node_id, node, network in c.fetchall():
      if not network.startswith(SITE + '@'):
        continue
      c.execute('SELECT name, value FROM option WHERE node_id = ?', (node_id, ))
      options = {}
      for name, value in c:
        options[name] = value
      nodes[node] = {
        'options': options
      }
  finally:
    conn.close()
  return json.dumps(nodes)


@analytics('/ping.status')
def ping_status():
  """Per host: how many seconds of the last minute went without an
  answer to a ping - 0: every ping was answered, 60: none was. (With a
  ping a second that is the number of missed pings, which is what the
  pages have always been given: the map calls 60 a dead switch, the
  build-up overview warns above 30.)

  A host is pinged every PING_INTERVAL seconds, so each answer stands
  for that many seconds. Where several collectors ping the same host,
  the one that heard the most counts."""
  ts = series('max by (host) (increase(icmp_rtt_seconds_count[1m]))')

  nodes = {}
  for x in ts:
    answered = float(x['value'][1]) * PING_INTERVAL
    nodes[x['metric']['host']] = max(0, min(60, int(round(60 - answered))))
  return json.dumps(nodes)


@analytics('/mon.alerts')
def mon_alerts():
  ts = series(
      'count(' +
      'label_replace(ALERTS{host!=""}, "instance", "$1", "host", "(.*)") ' +
      'or label_replace(ALERTS{instance!=""}, "instance", "$1", "instance", "(.*):[0-9]+")) ' +
      'by (instance)')
  nodes = {x['metric']['instance']: int(float(x['value'][1])) for x in ts}
  return json.dumps(nodes)


@analytics('/alerts.hosts')
def alerts_hosts():
  ts = series('ALERTS{alertstate="firing"}')
  alerts = collections.defaultdict(int)
  for alert in ts:
    host = hostname(alert['metric'])
    if host:
      alerts[host] = alerts[host] + 1
  return json.dumps(alerts)


@analytics('/snmp.saves')
def snmp_saves():
  ts = series('sum(snmp_exported_metrics_count) by (instance)')

  nodes = {x['metric']['instance']: {'metrics': int(float(x['value'][1]))}
           for x in ts}
  return json.dumps(nodes)


@analytics('/snmp.errors')
def snmp_errors():
  ts = series(
    'count(max_over_time(up{job=~"snmp.*",instance!=""}[5m]) == 0) by (instance)')

  nodes = {x['metric']['instance']: {
    'error': 'Timeout or Auth Error'} for x in ts}
  return json.dumps(nodes)


def per_sender(metric):
  """{sender: size} for a metric a log or backup server exports about
  OTHER machines. The sender's name is in the label "host" as the
  exporter writes it; a Prometheus that puts its own "host" label on
  every target keeps the exporter's as "exported_host". The largest
  value counts when several servers hold the same sender."""
  nodes = {}
  for x in series('max_over_time(%s[5m])' % metric):
    labels = x['metric']
    sender = labels.get('exported_host') or labels.get('host')
    if not sender:
      continue
    size = int(float(x['value'][1]))
    if size >= nodes.get(sender, {'size': -1})['size']:
      nodes[sender] = {'size': size}
  return nodes


@analytics('/syslog.status')
def syslog_status():
  return json.dumps(per_sender('syslog_log_bytes'))


@analytics('/rancid.status')
def rancid_status():
  return json.dumps(per_sender('rancid_config_bytes'))


@analytics('/dhcp.status')
def dhcp_status():
  """{network: {domain, vlan, usage, max}} from the DHCP server's
  lease history exporter (https://github.com/dhtech/lease2db): the
  label "name" is the plan's name of the network, <domain>@<network>."""
  dhcp_max = {
      x['metric'].get('name'): x['value'][1]
      for x in series('max(lease2db_scope_addresses) by (name)')}

  networks = {}
  for data in series('max(lease2db_scope_leases_active) by (name, vlan)'):
    name = data['metric'].get('name') or ''
    if '@' not in name or name not in dhcp_max:
      continue
    domain, network = name.split('@', 1)
    networks[network] = {
        'domain': domain,
        'vlan': data['metric'].get('vlan', ''),
        'usage': data['value'][1],
        'max': dhcp_max[name]
    }
  return json.dumps(networks)


@analytics('/switch.version')
def switch_version():
  return "{}"


def interface_variable(variable, key, bool_value=None, func=None, time=''):
  query = variable + '{instance!="",layer="access"}' + time
  if func:
    query = '%s(%s)' % (func, query)
  ts = series(query)
  nodes = collections.defaultdict(lambda: collections.defaultdict(dict))
  for data in ts:
    try:
      host = data['metric']['instance']
      iface = data['metric']['interface']
      if 'enum' in data['metric']:
        value = data['metric']['enum']
      else:
        value = data['value'][1]
      if bool_value is not None:
        value = (bool_value == value)
      nodes[host][iface][key] = value
      nodes[host][iface]['lastoid'] = data['metric']['index']
    except KeyError:
      # Ignore incomplete data
      continue
  return dict(nodes)


@analytics('/switch.interfaces')
def switch_interfaces():
  nodes = collections.defaultdict(lambda: collections.defaultdict(dict))
  variables = (
    ('ifOperStatus', 'status'),
    ('vlanTrunkPortDynamicStatus', 'trunk', 'trunking'),
    ('ifOutErrors', 'errors_out', None, 'rate', '[10m]'),
    ('ifInErrors', 'errors_in', None, 'rate', '[10m]'),
    ('ifHCInOctets', 'rx_10min', None, 'rate', '[10m]'),
    ('ifHCInOctets', 'rx', None, 'irate', '[10m]'),
    ('ifHCOutOctets', 'tx_10min', None, 'rate', '[10m]'),
    ('ifHCOutOctets', 'tx', None, 'irate', '[10m]'),
    ('ifAdminStatus', 'admin'),
    ('ifHighSpeed', 'speed'),
    ('dot1dStpPortState', 'stp'))

  results = []
  with concurrent.futures.ThreadPoolExecutor(max_workers=10) as e:
    for variables in e.map(lambda x: interface_variable(*x), variables):
      results.append(variables)

  for result in results:
    for node, ifaces in result.items():
      for iface, props in ifaces.items():
        nodes[node][iface].update(props)
  return json.dumps(nodes)


@analytics('/switch.vlans')
def switch_vlans():
  nodes = collections.defaultdict(dict)
  for data in series('changes(vtpVlanState{instance!=""}[5m])'):
    host = data['metric']['instance']
    vlan = data['metric']['index'].split('.', 1)[1]
    nodes[host][vlan] = 1

  for data in series('changes(dot1qVlanStaticRowStatus{instance!=""}[5m])'):
    host = data['metric']['instance']
    vlan = data['metric']['index']
    nodes[host][vlan] = 1
  return json.dumps(nodes)


@analytics('/switch.model')
def switch_model():
  ts = series(
    'changes(entPhysicalModelName{instance!="",index="1"}[5m])')

  nodes = {x['metric']['instance']: {'model': x['metric']['value']} for x in ts}
  return json.dumps(nodes)


@app.route('/healthz')
def healthz():
  """For a monitor: 200 when every source was gathered without an error
  within the last minute (or three gatherings, whichever is longer)."""
  limit = max(60, 3 * CACHE_TIME)
  now = time.time()
  stale = sorted(t for t, source in data_sources.items()
                 if now - source.updated > limit)
  if stale:
    return flask.Response('not gathered lately: %s\n' % ' '.join(stale),
                          status=503, mimetype='text/plain')
  return flask.Response('ok\n', mimetype='text/plain')


def gather(source):
  """Gather one source once. An error leaves what it had."""
  try:
    data_sources[source].data = data_sources[source].func()
    data_sources[source].updated = time.time()
    return True
  except Exception:
    traceback.print_exc(file=sys.stdout)
    sys.stdout.flush()
    return False


def fetch(source):
  while True:
    gather(source)
    time.sleep(CACHE_TIME)


_started = threading.Lock()
_running = False


def start():
  """Start the gathering threads - once, however often it is asked."""
  global _running
  with _started:
    if _running:
      return
    _running = True
    for source in data_sources:
      fetch_thread = threading.Thread(target=fetch, args=(source, ))
      fetch_thread.daemon = True
      fetch_thread.start()


def application(environ, start_response):
  """The WSGI entry: the gathering starts with the first request a
  worker process serves (after a server's fork, where threads would
  not have survived)."""
  start()
  return app(environ, start_response)


if __name__ == '__main__':
  start()
  # The gathering threads live in this process; the data is cached, so
  # one thread for serving is enough.
  app.run(host='127.0.0.1', threaded=False, port=5000)
