"""The tests run with Flask when it is installed, and without it too:
what is gathered and how is plain Python - only the test of the routes
themselves needs Flask (and is skipped without it)."""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
  import flask  # noqa: F401
  HAVE_FLASK = True
except ImportError:
  HAVE_FLASK = False

  class _Response(object):
    def __init__(self, data='', status=200, mimetype=None):
      self.data, self.status_code, self.mimetype = data, status, mimetype

  class _Flask(object):
    def __init__(self, name):
      self.routes = {}

    def route(self, path):
      def register(func):
        self.routes[path] = func
        return func
      return register

  sys.modules['flask'] = types.SimpleNamespace(Flask=_Flask, Response=_Response)
