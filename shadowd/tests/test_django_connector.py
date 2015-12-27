import unittest
import shadowd.django_connector
import django.http
import django.conf

class TestDjangoConnector(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        django.conf.settings.configure(DEBUG=True)

    def test_get_input(self):
        r = django.http.HttpRequest()
        r.GET = django.http.QueryDict('foo=bar')
        r.POST = django.http.QueryDict('foo=bar')
        r.COOKIES = {'foo': 'bar'}
        r.META = {'HTTP_FOO': 'bar', 'foo': 'bar'}

        i = shadowd.django_connector.InputDjango(r)
        i.gather_input()

        input = i.get_input()
        self.assertIn('GET|foo', input)
        self.assertEqual(input['GET|foo'], 'bar')
        self.assertIn('POST|foo', input)
        self.assertEqual(input['POST|foo'], 'bar')
        self.assertIn('COOKIE|foo', input)
        self.assertEqual(input['COOKIE|foo'], 'bar')
        self.assertIn('SERVER|HTTP_FOO', input)
        self.assertEqual(input['SERVER|HTTP_FOO'], 'bar')
        self.assertNotIn('SERVER|foo', input)

    def test_get_input_array(self):
        r = django.http.HttpRequest()
        r.GET = django.http.QueryDict('foo=bar1&foo=bar2')
        r.POST = django.http.QueryDict('foo=bar1&foo=bar2')

        i = shadowd.django_connector.InputDjango(r)
        i.gather_input()

        input = i.get_input()
        self.assertIn('GET|foo|0', input)
        self.assertEqual(input['GET|foo|0'], 'bar1')
        self.assertIn('GET|foo|1', input)
        self.assertEqual(input['GET|foo|1'], 'bar2')
        self.assertIn('POST|foo|0', input)
        self.assertEqual(input['POST|foo|0'], 'bar1')
        self.assertIn('POST|foo|1', input)
        self.assertEqual(input['POST|foo|1'], 'bar2')

    def test_defuse_input(self):
        r = django.http.HttpRequest()
        r.GET = django.http.QueryDict('foo=bar')
        r.POST = django.http.QueryDict('foo=bar')
        r.COOKIES = {'foo': 'bar'}
        r.META = {'HTTP_FOO': 'bar'}

        threats = ['GET|foo', 'POST|foo', 'COOKIE|foo', 'SERVER|HTTP_FOO']

        i = shadowd.django_connector.InputDjango(r)
        self.assertTrue(i.defuse_input(threats))
        self.assertIn('foo', r.GET)
        self.assertEqual(r.GET['foo'], '')
        self.assertIn('foo', r.POST)
        self.assertEqual(r.POST['foo'], '')
        self.assertIn('foo', r.COOKIES)
        self.assertEqual(r.COOKIES['foo'], '')
        self.assertIn('HTTP_FOO', r.META)
        self.assertEqual(r.META['HTTP_FOO'], '')
