import connexion
import time
import requests
import json
from typing import Dict
from typing import Tuple
from typing import Union

from openapi_server.models.close_conn_info import CloseConnInfo  # noqa: E501
from openapi_server.models.delete_file_info import DeleteFileInfo  # noqa: E501
from openapi_server.models.error_message import ErrorMessage  # noqa: E501
from openapi_server.models.open_c2_response import OpenC2Response  # noqa: E501
from openapi_server import util


content_type_header = {'Content-type': 'application/json'}
from_ip = "172.26.0.1"

def get_actuator_url(actuator_ip):
  actuator_url = "http://" + actuator_ip + ":8080/api/openc2"
  return actuator_url

def close_connection_post(body):  # noqa: E501
    """Close a TCP connection on OpenC2 consumer/actuator
    Send an OpenC2 command to consumer to close a TCP connection # noqa: E501
    """
    if connexion.request.is_json:
      close_conn_info = CloseConnInfo.from_dict(connexion.request.get_json())  # noqa: E501
      actuator_ip = close_conn_info.actuator_ip #IP del Consumer OpenC2
      pid = close_conn_info.pid #PID de la conn
      dst_ip = close_conn_info.dst_ip #Dst IP conn
      src_port = close_conn_info.src_port #Source port
      dst_port = close_conn_info.dst_port #Dest port
      timestamp = time.time()
      command_json = {
        	"headers": {
        		"request_id": "request-" + str(timestamp),
        		"created": timestamp,
        		"from": from_ip,
        		"to": actuator_ip
        	},
        	"request": {
        		"action": "deny",
  			"target": {
    				"ipv4_connection": {
      					"pid": pid,
      					"dst_port": dst_port,
      					"dst_addr": dst_ip,
      					"src_port": src_port,
      					"src_addr": actuator_ip
    				}
  			},
  			"args": {}
        	}
        }
        
      actuator_url = get_actuator_url(actuator_ip)
      json_data = json.dumps(command_json)
      actuator_response = requests.post(actuator_url, data=json_data, headers=content_type_header, verify=False) #POST al actuator
        
      if actuator_response.status_code == 200:
        json_resp = json.loads(actuator_response.content)
        openc2_response = OpenC2Response.from_dict(json_resp)
          
        return openc2_response #Se devuelve el schema definido a Shuffle
    
    return None



def delete_file_post(body):  # noqa: E501
    """Delete a file on OpenC2 consumer/actuator
    Send an OpenC2 command to consumer to delete a file # noqa: E501
    """
    if connexion.request.is_json:
        delete_file_info = DeleteFileInfo.from_dict(connexion.request.get_json())  # noqa: E501
        actuator_ip = delete_file_info.actuator_ip #IP del Consumer OpenC2
        file_path = delete_file_info.file_path #Path del file a eliminar en Consumer
        timestamp = time.time()
        command_json = {
        	"headers": {
        		"request_id": "request-" + str(timestamp),
        		"created": timestamp,
        		"from": from_ip,
        		"to": actuator_ip
        	},
        	"request": {
        		"action": "delete",
  			"target": {
    				"file": {
      					"path": file_path
    				}
  			},
  			"args": {}
        	}
        }
        
        actuator_url = get_actuator_url(actuator_ip)
        json_data = json.dumps(command_json)
        actuator_response = requests.post(actuator_url, data=json_data, headers=content_type_header, verify=False) #POST al actuator
        
        if actuator_response.status_code == 200:
          json_resp = json.loads(actuator_response.content)
          openc2_response = OpenC2Response.from_dict(json_resp)
          
          return openc2_response #Se devuelve el schema definido a Shuffle
        
        
    return None
