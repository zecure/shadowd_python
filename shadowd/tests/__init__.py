import unittest

def test_all():
	return unittest.TestLoader().loadTestsFromNames([
        'shadowd.tests.test_connector',
    ])
