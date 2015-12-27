import unittest

def test_all():
    return unittest.TestLoader().loadTestsFromNames([
        'shadowd.tests.test_connector',
        'shadowd.tests.test_django_connector',
        'shadowd.tests.test_werkzeug_connector',
    ])
