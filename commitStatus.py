import os
import json
import logging
import urllib.parse

from base64 import b64decode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    detail = event["detail"]
    # print(json.dumps(detail, indent =2))
    print(detail["build-status"])
    