# Copyright 2018 dhtech
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file
import collections
import concurrent.futures
import flask
import functools
import json
import socket
import sqlite3
import sys
import threading
import time
import traceback
import urllib
import urllib2


DB_FILE = '/etc/ipplan.db'
CACHE_TIME = 10


class DataSource(object):
  def __init__(self, data, func):
    self.data = data
    self.func = func


app = flask.Flask(__name__)
data_sources = {}


def analytics(t):
  def handler(func):
    data_sources[t] = DataSource("", func)
    @app.route(t)
    @functools.wraps(func)
    def wrapper():
      return data_sources[t].data
    return wrapper
  return handler


def prometheus(query):
  host = 'http://prometheus.event.dreamhack.se:9090'
  url = '{host}/api/v1/query?query={query}&time={time}'

  socket.setdefaulttimeout(10)

  o = urllib2.urlopen(url.format(
    query=urllib.quote(query), time=int(time.time()), host=host))

  return o.read()


@analytics('/event.hosts')
def event_hosts():
  conn = sqlite3.connect(DB_FILE)
  c = conn.cursor()
  c.execute('SELECT h.node_id, h.name, n.name '
            'FROM host h, network n WHERE n.node_id = h.network_id')

  nodes = {}
  for node_id, node, network in c.fetchall():
    if not network.startswith('EVENT@'):
      continue
    c.execute('SELECT name, value FROM option WHERE node_id = ?', (node_id, ))
    options = {}
    for name, value in c:
      options[name] = value
    nodes[node] = {
      'options': options
    }
  return json.dumps(nodes)


@analytics('/ping.status')
def ping_status():
  result = json.loads(prometheus('changes(icmp_rtt_seconds_sum[1m])'))
  ts = result['data']['result']

  nodes = {x['metric']['host']: 60-int(x['value'][1]) for x in ts}
  return json.dumps(nodes)


@analytics('/mon.alerts')
def mon_alerts():
  result = json.loads(prometheus(
      'count(' +
      'label_replace(ALERTS{host!=""}, "instance", "$1", "host", "(.*)") ' +
      'or label_replace(ALERTS{instance!=""}, "instance", "$1", "instance", "(.*):[0-9]+")) ' +
      'by (instance)'))
  ts = result['data']['result']
  nodes = {x['metric']['instance']: int(x['value'][1]) for x in ts}
  return json.dumps(nodes)


@analytics('/alerts.hosts')
def alerts_hosts():
  result = json.loads(prometheus('ALERTS{alertstate="firing"}'))
  ts = result['data']['result']
  alerts = collections.defaultdict(int)
  for alert in ts:
    labels = alert['metric']
    if 'host' in labels:
      host = labels['host']
      if ':' in host:
        host = host.split(':')[0]
      alerts[host] = alerts[host] + 1
    elif 'instance' in labels:
      host = labels['instance']
      if ':' in host:
        host = host.split(':')[0]
      alerts[host] = alerts[host] + 1
  return json.dumps(alerts)


@analytics('/snmp.saves')
def snmp_saves():
  result = json.loads(prometheus('sum(snmp_exported_metrics_count) by (instance)'))
  ts = result['data']['result']

  nodes = {x['metric']['instance']: {'metrics': int(x['value'][1])} for x in ts}
  return json.dumps(nodes)


@analytics('/snmp.errors')
def snmp_errors():
  result = json.loads(prometheus(
    'count(max_over_time(up{job=~"snmp.*",instance!=""}[5m]) == 0) by (instance)'))
  ts = result['data']['result']

  nodes = {x['metric']['instance']: {
    'error': 'Timeout or Auth Error'} for x in ts}
  return json.dumps(nodes)


@analytics('/syslog.status')
def syslog_status():
  result = json.loads(prometheus('max_over_time(syslog_log_bytes[5m])'))
  ts = result['data']['result']
  nodes = {x['metric']['host']: {'size': int(x['value'][1])} for x in ts}
  return json.dumps(nodes)


@analytics('/rancid.status')
def rancid_status():
  result = json.loads(prometheus('max_over_time(rancid_config_bytes[5m])'))
  ts = result['data']['result']
  nodes = {x['metric']['host']: {'size': int(x['value'][1])} for x in ts}
  return json.dumps(nodes)


@analytics('/dhcp.status')
def dhcp_status():
  result = json.loads(prometheus('dhcp_leases_current_count'))
  dhcp_usage = result['data']['result']
  result = json.loads(prometheus('dhcp_leases_max_count'))
  dhcp_max = {
      x['metric']['network']: x['value'][1]
      for x in result['data']['result']}

  networks = {}
  for data in dhcp_usage:
    domain, network = data['metric']['network'].split('@', 2)
    vlan = data['metric']['vlan']
    networks[network] = {
        'domain': domain,
        'vlan': vlan,
        'usage': data['value'][1],
        'max': dhcp_max[data['metric']['network']]
    }
  return json.dumps(networks)


@analytics('/switch.version')
def switch_version():
  return "{}"


def interface_variable(variable, key, bool_value=None, func=None, time=''):
  query = variable + '{instance!="",layer="access"}' + time
  if func:
    query = '%s(%s)' % (func, query)
  result = json.loads(prometheus(query))
  ts = result['data']['result']
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
    ('ifAdminStatus', 'admin'),
    ('ifHighSpeed', 'speed'),
    ('dot1dStpPortState', 'stp'))

  results = []
  with concurrent.futures.ThreadPoolExecutor(max_workers=10) as e:
    for variables in e.map(lambda x: interface_variable(*x), variables):
      results.append(variables)

  for result in results:
    for node, ifaces in result.iteritems():
      for iface, props in ifaces.iteritems():
        nodes[node][iface].update(props)
  return json.dumps(nodes)


@analytics('/switch.vlans')
def switch_vlans():
  result = json.loads(prometheus('changes(vtpVlanState{instance!=""}[5m])'))
  ts = result['data']['result']

  nodes = collections.defaultdict(dict)
  for data in ts:
    host = data['metric']['instance']
    vlan = data['metric']['index'].split('.', 1)[1]
    nodes[host][vlan] = 1

  result = json.loads(prometheus('changes(dot1qVlanStaticRowStatus{instance!=""}[5m])'))
  ts = result['data']['result']
  nodes = collections.defaultdict(dict)
  for data in ts:
    host = data['metric']['instance']
    vlan = data['metric']['index']
    nodes[host][vlan] = 1
  return json.dumps(nodes)


@analytics('/switch.model')
def switch_model():
  result = json.loads(prometheus(
    'changes(entPhysicalModelName{instance!="",index="1"}[5m])'))
  ts = result['data']['result']

  nodes = {x['metric']['instance']: {'model': x['metric']['value']} for x in ts}
  return json.dumps(nodes)


def fetch(sources, source):
  while True:
    try:
        sources[source].data = sources[source].func()
    except:
        traceback.print_exc(file=sys.stdout)

    time.sleep(CACHE_TIME)


if __name__ == '__main__':
  for source in data_sources:
      fetch_thread = threading.Thread(target=fetch,args=(data_sources, source))
      fetch_thread.daemon = True
      fetch_thread.start()
  # The background thread will be multiplied with the number of flask
  # threads, so keep just one thread for serving. The data is cached anyway
  # so it should be fast.
  app.run(debug=True, threaded=False, port=5000)

