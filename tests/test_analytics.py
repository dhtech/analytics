"""What analytics gathers, with a Prometheus made of a dict."""
import json
import sqlite3

import pytest

import conftest
import analytics


def one(labels, value=1):
  return {'metric': labels, 'value': [0, str(value)]}


class Prometheus(object):
  """Answers queries from a table {query: [series]}; remembers them."""

  def __init__(self, table):
    self.table = table
    self.asked = []

  def __call__(self, query):
    self.asked.append(query)
    return json.dumps({'status': 'success', 'data': {
        'resultType': 'vector', 'result': self.table.get(query, [])}}).encode()


@pytest.fixture
def prom(monkeypatch):
  def use(table):
    fake = Prometheus(table)
    monkeypatch.setattr(analytics, 'prometheus', fake)
    return fake
  return use


def answer(path):
  return json.loads(analytics.data_sources[path].func())


def test_every_address_the_pages_ask_exists():
  # dhmap's dhmon.js and buildstatus ask these (under /analytics/)
  for path in ('/ping.status', '/snmp.saves', '/switch.model',
               '/switch.interfaces', '/dhcp.status', '/switch.vlans',
               '/alerts.hosts', '/snmp.errors', '/event.hosts',
               '/rancid.status', '/syslog.status', '/mon.alerts',
               '/switch.version'):
    assert path in analytics.data_sources, path
    # before the first gathering: an empty document, not nothing
    assert json.loads(analytics.data_sources[path].data) == {}


def test_alerts_are_counted_per_host(prom):
  prom({'ALERTS{alertstate="firing"}': [
      one({'alertname': 'NodeDown', 'host': 'icmp1.event.dreamhack.se',
           'instance': 'icmp1.event.dreamhack.se:9100'}),
      one({'alertname': 'FilesystemAlmostFull',
           'host': 'icmp1.event.dreamhack.se'}),
      one({'alertname': 'X', 'instance': 'd23-a.event.dreamhack.local:161'}),
      one({'alertname': 'NoHost'})]})
  assert answer('/alerts.hosts') == {'icmp1.event.dreamhack.se': 2,
                                     'd23-a.event.dreamhack.local': 1}


PINGS = 'max by (host) (increase(icmp_rtt_seconds_count[1m]))'


def test_ping_is_missed_answers_in_the_last_minute(prom):
  # a ping a second (the default): one answer is one second
  prom({PINGS: [
      one({'host': 'd23-a.event.dreamhack.local'}, 60),
      one({'host': 'd24-a.event.dreamhack.local'}, '57.0'),
      one({'host': 'd25-a.event.dreamhack.local'}, 0),
      # what Prometheus estimates is no whole number, and may overshoot
      one({'host': 'd26-a.event.dreamhack.local'}, '61.02'),
      one({'host': 'd27-a.event.dreamhack.local'}, '29.6')]})
  assert answer('/ping.status') == {'d23-a.event.dreamhack.local': 0,
                                    'd24-a.event.dreamhack.local': 3,
                                    'd25-a.event.dreamhack.local': 60,
                                    'd26-a.event.dreamhack.local': 0,
                                    'd27-a.event.dreamhack.local': 30}


def test_ping_every_ten_seconds_is_the_same_scale(prom, monkeypatch):
  # six pings a minute: each answer stands for ten seconds, and the
  # pages' thresholds (60 = dead, above 30 = warn) mean what they did
  monkeypatch.setattr(analytics, 'PING_INTERVAL', 10.0)
  prom({PINGS: [
      one({'host': 'all.event.dreamhack.local'}, 6),
      one({'host': 'most.event.dreamhack.local'}, '4.8'),
      one({'host': 'few.event.dreamhack.local'}, 2),
      one({'host': 'none.event.dreamhack.local'}, 0),
      one({'host': 'over.event.dreamhack.local'}, '7.2')]})
  assert answer('/ping.status') == {'all.event.dreamhack.local': 0,
                                    'most.event.dreamhack.local': 12,
                                    'few.event.dreamhack.local': 40,
                                    'none.event.dreamhack.local': 60,
                                    'over.event.dreamhack.local': 0}


def test_dhcp_usage_comes_from_the_lease_history(prom):
  fake = prom({
      'max(lease2db_scope_addresses) by (name)': [
          one({'name': 'EVENT@A-ARKHERON-HSI'}, 60),
          one({'name': 'EVENT@B-FREEPLAY'}, 500)],
      'max(lease2db_scope_leases_active) by (name, vlan)': [
          one({'name': 'EVENT@A-ARKHERON-HSI', 'vlan': '410'}, 12),
          one({'name': 'EVENT@B-FREEPLAY', 'vlan': ''}, 0),
          one({'name': 'no-domain', 'vlan': '7'}, 1),
          one({'name': 'EVENT@NO-SIZE', 'vlan': '8'}, 1)]})
  # the shape dhmap reads: usage and max per network, found by its vlan
  assert answer('/dhcp.status') == {
      'A-ARKHERON-HSI': {'domain': 'EVENT', 'vlan': '410',
                         'usage': '12', 'max': '60'},
      'B-FREEPLAY': {'domain': 'EVENT', 'vlan': '', 'usage': '0',
                     'max': '500'}}
  assert len(fake.asked) == 2


def test_a_log_servers_senders_whatever_the_label_is_called(prom):
  # a Prometheus that labels every target with its own "host" keeps the
  # exporter's label as "exported_host"; two log servers hold the same
  # sender - the larger file counts
  prom({'max_over_time(syslog_log_bytes[5m])': [
      one({'exported_host': 'd23-a.event.dreamhack.local',
           'host': 'syslog1.event.dreamhack.se', 'severity': 'all'}, 900),
      one({'exported_host': 'd23-a.event.dreamhack.local',
           'host': 'syslog2.event.dreamhack.se', 'severity': 'all'}, 1000),
      one({'exported_host': 'd23-a.event.dreamhack.local',
           'host': 'syslog1.event.dreamhack.se', 'severity': 'err'}, 10),
      one({'host': 'old-style-sender', 'severity': 'all'}, 5),
      one({'severity': 'all'}, 5)]})
  assert answer('/syslog.status') == {
      'd23-a.event.dreamhack.local': {'size': 1000},
      'old-style-sender': {'size': 5}}


def test_nothing_exported_is_an_empty_answer_not_an_error(prom):
  prom({})
  for path in ('/ping.status', '/snmp.saves', '/snmp.errors',
               '/syslog.status', '/rancid.status', '/dhcp.status',
               '/switch.interfaces', '/switch.vlans', '/switch.model',
               '/alerts.hosts', '/mon.alerts'):
    assert answer(path) == {}, path


def test_switch_interfaces_are_put_together_per_port(prom):
  where = '{instance!="",layer="access"}'
  port = {'instance': 'd23-a', 'interface': 'Gi1/0/5', 'index': '10105'}
  prom({
      'ifOperStatus' + where: [one(dict(port, enum='up'))],
      'vlanTrunkPortDynamicStatus' + where: [one(dict(port, enum='trunking'))],
      'ifHighSpeed' + where: [one(port, 1000)],
      'rate(ifInErrors' + where + '[10m])': [one(port, '0.5')],
      'ifAdminStatus' + where: [one({'instance': 'incomplete'})]})
  assert answer('/switch.interfaces') == {'d23-a': {'Gi1/0/5': {
      'status': 'up', 'trunk': True, 'speed': '1000', 'errors_in': '0.5',
      'lastoid': '10105'}}}


@pytest.fixture
def plan(tmp_path, monkeypatch):
  path = tmp_path / 'ipplan.db'
  conn = sqlite3.connect(str(path))
  conn.executescript('''
      CREATE TABLE network(node_id, name);
      CREATE TABLE host(node_id, name, network_id);
      CREATE TABLE option(node_id, name, value);
      INSERT INTO network VALUES (1, 'EVENT@D-ACCESS'), (2, 'STO3@SERVERS');
      INSERT INTO host VALUES (10, 'd23-a.event.dreamhack.local', 1),
                              (11, 'web.tech.dreamhack.se', 2);
      INSERT INTO option VALUES (10, 'layer', 'access'), (11, 'os', 'debian');
  ''')
  conn.commit()
  conn.close()
  monkeypatch.setattr(analytics, 'DB_FILE', str(path))
  return path


def test_the_hosts_are_the_sites_own(plan, monkeypatch):
  assert answer('/event.hosts') == {
      'd23-a.event.dreamhack.local': {'options': {'layer': 'access'}}}
  monkeypatch.setattr(analytics, 'SITE', 'STO3')
  assert list(answer('/event.hosts')) == ['web.tech.dreamhack.se']


def test_a_failed_gathering_keeps_the_last_answer(prom, capsys, monkeypatch):
  prom({'ALERTS{alertstate="firing"}': [one({'host': 'a'})]})
  assert analytics.gather('/alerts.hosts') is True
  assert json.loads(analytics.data_sources['/alerts.hosts'].data) == {'a': 1}

  def away(query):
    raise OSError('connection refused')
  monkeypatch.setattr(analytics, 'prometheus', away)
  assert analytics.gather('/alerts.hosts') is False
  assert json.loads(analytics.data_sources['/alerts.hosts'].data) == {'a': 1}
  assert 'connection refused' in capsys.readouterr().out


def test_the_gathering_starts_once(monkeypatch):
  started = []

  class Thread(object):
    def __init__(self, target, args):
      self.daemon = False
      started.append(args[0])

    def start(self):
      assert self.daemon is True

  monkeypatch.setattr(analytics.threading, 'Thread', Thread)
  monkeypatch.setattr(analytics, '_running', False)
  analytics.start()
  analytics.start()
  assert sorted(started) == sorted(analytics.data_sources)


@pytest.mark.skipif(not conftest.HAVE_FLASK, reason='Flask is not installed')
def test_the_routes_serve_what_was_gathered(prom):
  prom({'ALERTS{alertstate="firing"}': [one({'host': 'a'})]})
  analytics.gather('/alerts.hosts')
  client = analytics.app.test_client()
  got = client.get('/alerts.hosts')
  assert got.status_code == 200 and got.mimetype == 'application/json'
  assert got.get_json() == {'a': 1}
  assert client.get('/switch.version').get_json() == {}
