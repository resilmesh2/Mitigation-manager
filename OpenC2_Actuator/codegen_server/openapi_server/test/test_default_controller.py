import unittest

from flask import json

from openapi_server.models.error_message import ErrorMessage  # noqa: E501
from openapi_server.models.open_c2_response import OpenC2Response  # noqa: E501
from openapi_server.test import BaseTestCase


class TestDefaultController(BaseTestCase):
    """DefaultController integration test stubs"""

    def test_api_openc2_post(self):
        """Test case for api_openc2_post

        Execute an OpenC2 command
        """
        body = None
        headers = { 
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }
        response = self.client.open(
            '/api/openc2',
            method='POST',
            headers=headers,
            data=json.dumps(body),
            content_type='application/json')
        self.assert200(response,
                       'Response body is : ' + response.data.decode('utf-8'))


if __name__ == '__main__':
    unittest.main()
