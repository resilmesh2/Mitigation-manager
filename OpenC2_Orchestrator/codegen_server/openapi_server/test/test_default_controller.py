import unittest

from flask import json

from openapi_server.models.close_conn_info import CloseConnInfo  # noqa: E501
from openapi_server.models.delete_file_info import DeleteFileInfo  # noqa: E501
from openapi_server.models.error_message import ErrorMessage  # noqa: E501
from openapi_server.models.open_c2_response import OpenC2Response  # noqa: E501
from openapi_server.test import BaseTestCase


class TestDefaultController(BaseTestCase):
    """DefaultController integration test stubs"""

    def test_close_connection_post(self):
        """Test case for close_connection_post

        Close a TCP connection on OpenC2 consumer/actuator
        """
        close_conn_info = {"src_port":6,"actuator_ip":"actuator_ip","dst_port":1,"pid":0,"dst_ip":"dst_ip"}
        headers = { 
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }
        response = self.client.open(
            '/close_connection',
            method='POST',
            headers=headers,
            data=json.dumps(close_conn_info),
            content_type='application/json')
        self.assert200(response,
                       'Response body is : ' + response.data.decode('utf-8'))

    def test_delete_file_post(self):
        """Test case for delete_file_post

        Delete a file on OpenC2 consumer/actuator
        """
        delete_file_info = {"file_path":"file_path","actuator_ip":"actuator_ip"}
        headers = { 
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }
        response = self.client.open(
            '/delete_file',
            method='POST',
            headers=headers,
            data=json.dumps(delete_file_info),
            content_type='application/json')
        self.assert200(response,
                       'Response body is : ' + response.data.decode('utf-8'))


if __name__ == '__main__':
    unittest.main()
