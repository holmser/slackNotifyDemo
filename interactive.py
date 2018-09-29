# This function is triggered via API Gateway when a user acts on the Slack interactive message sent by approval_requester.py.

from urllib.parse import parse_qs
import json
import os
import boto3
import hmac
import hashlib
from base64 import b64decode

SLACK_SIGNING_SECRET = os.environ['SLACK_SIGNING_SECRET']

#Triggered by API Gateway
#It kicks off a particular CodePipeline project
def lambda_handler(event, context):
	#print("Received event: " + json.dumps(event, indent=2))
    body = parse_qs(event['body'])
    payload = json.loads(body['payload'][0])

	# Validate Slack signature
    if authenticate_request(event):
        send_slack_message(json.loads(payload['actions'][0]['value']))
		
		# This will replace the interactive message with a simple text response.
		# You can implement a more complex message update if you would like.
        return  {
            "isBase64Encoded": "false",
            "statusCode": 200,
            "body": "{\"text\": \"The approval has been processed\"}"
            }
    else:
        return  {
            "isBase64Encoded": "false",
            "statusCode": 403,
            "body": "{\"error\": \"This request does not include a vailid verification token.\"}"
            }

def authenticate_request(request):
    # Get values 
    body = request["body"]
    timestamp = request["headers"]["X-Slack-Request-Timestamp"]
    # Decrypt signing secret using KMS
    key = boto3.client('kms').decrypt(CiphertextBlob=b64decode(SLACK_SIGNING_SECRET))['Plaintext']
    #key = decrypted.encode()

    request_sig = request["headers"]['X-Slack-Signature']
    # Cat values together to be hashed
    sig_basestring = "v0:"+timestamp + ":" + body
    
    computed_sig = "v0=" + hmac.new(key, sig_basestring.encode(), hashlib.sha256).hexdigest()
    print(computed_sig, type(computed_sig), request_sig, type(request_sig))

    return hmac.compare_digest(computed_sig, request_sig)

def send_slack_message(action_details):
    print(action_details)
    codepipeline_status = "Approved" if action_details["approve"] else "Rejected"
    codepipeline_name = action_details["codePipelineName"]
    action = action_details["action"]
    token = action_details["codePipelineToken"]
    
    client = boto3.client('codepipeline')
    response_approval = client.put_approval_result(
                            pipelineName=codepipeline_name,
                            stageName='Approval',
                            actionName= action,
                            result={'summary':'','status':codepipeline_status},
                            token=token)
    print(response_approval)