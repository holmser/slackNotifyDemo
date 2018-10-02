from urllib.parse import parse_qs
import json
import os
import boto3
import hmac
import hashlib
import base64
from base64 import b64decode
from botocore.exceptions import ClientError

# Triggered by API Gateway
# It kicks off a particular CodePipeline project
def lambda_handler(event, context):
    print(json.dumps(event, indent=2))
    body = parse_qs(event['body'])
    payload = json.loads(body['payload'][0])
    # Validate Slack signature
    if authenticate_request(event):
        send_slack_message(json.loads(payload['actions'][0]['value']))
		
		# This will replace the interactive message with a simple text response.
		# You can implement a more git a message update if you would like.
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
    """
    Slack provides a signing secret with each request that allows us to use HMAC 
    authenticate the request.  This is the same system that AWS uses to authenticate 
    requests.  The formula for this is to cat together the timestamp and request, 
    then use sha256 to hash using the signing key that Slack provides us.  We then 
    compare that to the signature provided by Slack in the request header.  We can
    use the timestamp to mitigate replay attacks as well.
    """

    # Request Slack Signing secret from AWS Secret Manager
    secret = json.loads(get_secret())
    key = secret["SLACK_SIGNING_SECRET"].encode()

    body = request["body"]
    timestamp = request["headers"]["X-Slack-Request-Timestamp"]

    # Decrypt signing secret using KMS
    # key = boto3.client('kms').decrypt(CiphertextBlob=b64decode(SLACK_SIGNING_SECRET))['Plaintext']
    #key = decrypted.encode()
    print("secret", secret)
    
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
# https://aws.amazon.com/developers/getting-started/python/

def get_secret():

    secret_name = "SlackSigningSecret"
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )

    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return secret
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return decoded_binary_secret
