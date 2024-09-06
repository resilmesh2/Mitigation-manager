import connexion
import json
import subprocess
import datetime
from typing import Dict
from typing import Tuple
from typing import Union

from openapi_server.models.error_message import ErrorMessage  # noqa: E501
from openapi_server.models.open_c2_response import OpenC2Response  # noqa: E501
from openapi_server import util

def create_headers(request_id, created, from_ip, to_ip):
  json_headers = {
        	"request_id": request_id,
        	"created": created,
        	"from": from_ip,
        	"to": to_ip
        }
  return json_headers
  
  
def create_response(status, status_text, results):
  json_response = {
  		"status": status, 
  		"status_text": status_text,
  		"results": results
  	}
  return json_response
  
  
def delete_file(path): 
  return_code = subprocess.call(["rm", "-f", path])
  return return_code
  
def close_conn(ip_dst, pid):
  #Pensar si usar algun campo mas para hacer una regla iptables
  #subprocess.call(["iptables", "-A", "OUTPUT", "-m", "hostname", "--host", ip_dst, "-j", "DROP"])
  return_code = subprocess.call(["kill", "-9", str(pid)])
  return return_code

def api_openc2_post(body):  # noqa: E501
    """Execute an OpenC2 command
    Send an OpenC2 command to OpenC2 actuator # noqa: E501
    """
    
    if connexion.request.is_json:
      inicio = datetime.datetime.now()
      body = connexion.request.get_json()
      
      action_type = body['request']['action']
      if action_type == "delete":
        code = delete_file(body['request']['target']['file']['path']) #Se pasa la ruta
        response = create_response(200, "OK", "File " + body['request']['target']['file']['path'] + " deleted")
        
        if code != 0:
          response = create_response(500, "Error", "Failed deleting file")
      
      elif  action_type == "deny":
        code = close_conn(body['request']['target']['ipv4_connection']['dst_addr'], body['request']['target']['ipv4_connection']['pid'])
        response = create_response(200, "OK", "Connection to " + body['request']['target']['ipv4_connection']['dst_addr'] + ":" + str(body['request']['target']['ipv4_connection']['dst_port']) + " closed.")
        
        if code != 0:
          response = create_response(500, "Error", "Failed to close connection")
      
      
      headers = create_headers(body['headers']['request_id'], body['headers']['created'], body['headers']['to'], body['headers']['from'])
      actuator_response = {
      		"headers": headers,
            "command_response": response
      }

      tiempo = str(datetime.datetime.now() - inicio)
      print("TIEMPO CONSUMER: ", tiempo)
      return actuator_response
      
    
    return None
