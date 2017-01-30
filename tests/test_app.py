
from mock import patch
from unittest import TestCase, skip
import hollowman.upstream
from hollowman.app import application
from collections import namedtuple


class DummyResponse(object):

    def __init__(self, headers={}):
        self.headers = headers
        self.content = None
        self.status_code = 200


class TestApp(TestCase):

    def test_remove_transfer_encoding_header(self):
        mock_response = DummyResponse(headers={"Transfer-Encoding": "chunked"})
        with patch.object(hollowman.upstream, 'replay_request', return_value=mock_response) as replay_mock:
            with application.test_client() as client:
                response = client.get("/v2/apps")
                self.assertTrue("Content-Encoding" not in response.headers)
                self.assertEqual(200, response.status_code)

                response = client.get("/ui/main.css")
                self.assertTrue("Content-Encoding" not in response.headers)
                self.assertEqual(200, response.status_code)

                self.assertEqual(2, replay_mock.call_count)

    def test_index_path(self):
        response = application.test_client().open('/')

        self.assertEqual(response.status_code, 301)
        self.assertTrue('Location' in response.headers)

    def test_ui_path(self):
        Response = namedtuple(
            'Response',
            [
                "headers",
                "content",
                "status_code"
            ]
        )

        with patch.object(hollowman.upstream, 'replay_request') as replay_request_mock:
            replay_request_mock.return_value = Response(
                headers={
                    "foo": "bar",
                    "Transfer-Encoding": 123
                },
                content="foofoofoofoofoofoo",
                status_code=301
            )
            response = application.test_client().open('/ui/foo/bar')
            self.assertEqual(response.status_code, 301)

    @skip('Need to find a way to test this. Any ideas ?')
    def test_apiv2_path(self):
        pass

    def test_fail_healthcheck(self):
        Response = namedtuple('Response', ["status_code"])

        with patch('hollowman.app.requests.get') as get_mock:
            get_mock.return_value = Response(status_code=404)
            response = application.test_client().open('/healthcheck')
            self.assertEqual(response.status_code, 404)

    def test_200_healthcheck(self):
        Response = namedtuple('Response', ["status_code"])

        with patch('hollowman.app.requests.get') as get_mock:
            get_mock.return_value = Response(status_code=200)
            response = application.test_client().open('/healthcheck')
            self.assertEqual(response.status_code, 200)