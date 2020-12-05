import boto3, os, sys
from kubernetes import client, config
import kubernetes.client
import subprocess
from slack import WebClient
from slack.errors import SlackApiError

dir_path = os.path.dirname(os.path.realpath(__file__))

# Declaring the AWS account details
if sys.argv[1] == "prod":
  account_id = "<AWS_ACCOUNT_NUMBER>"
  env = "prod"
  channel_name = "#prod-alerts"
elif sys.argv[1] == "stage":
  account_id = "<AWS_ACCOUNT_NUMBER>"
  env = "stage"
  channel_name = "#non-prod-alerts"
elif sys.argv[1] == "dev":
  account_id = "<AWS_ACCOUNT_NUMBER>"
  env = "dev"
  channel_name = "#non-prod-alerts"
else:
  print("Invalid Source Environment")

# Declare instance id
instance_id = sys.argv[2]

# Slack Configuration
slack_token = "<SLACK_TOKEN>"

# Configuring the Kubeconfig for the target environment
kubeconfig = dir_path + "<kubeconfig_path>" + env + "/kubeconfig"

# aws config
sts_client = boto3.client('sts')
assumed_role_object = sts_client.assume_role(
  RoleArn="arn:aws:iam::" + account_id + ":role/Administrator",
  RoleSessionName="AssumeRoleSession"
)

credentials = assumed_role_object['Credentials']

ec2_resource = boto3.client(
  'ec2',
  aws_access_key_id=credentials['AccessKeyId'],
  aws_secret_access_key=credentials['SecretAccessKey'],
  aws_session_token=credentials['SessionToken'],
)

# Configs can be set in Configuration class directly or using helper utility
config.load_kube_config(kubeconfig)
api_instance = kubernetes.client.CoreV1Api()

response = ec2_resource.describe_instances()

# Node table which will have all the running instances.
nodetable = []

# Function for sending slack messages
def slack_notify(channel_name, slack_token, ip):
  client = WebClient(token=slack_token)
  try:
    response = client.chat_postMessage(
      channel=channel_name,
      attachments=[
        {
          "color": "#4BB543",
          "text": "Node `" + ip + "` has been removed from `" + env + "` Kubernetes cluster",
        }
      ]
    )
  except SlackApiError as e:
    assert e.response["error"]  # str like 'invalid_auth', 'channel_not_found'
    print(f"Got an error: {e.response['error']}")

for reservation in response["Reservations"]:
  for instance in reservation["Instances"]:
    try:
      if (instance_id == instance["InstanceId"]):
        # print(instance["InstanceId"])
        nodeip = instance["PrivateIpAddress"]
        # Add Running nodes to the list to be compared later
        nodetable.append(nodeip)
    except:
      print("Instance Terminated")

listnodes = api_instance.list_node()
for i in listnodes.items:
  node = i.metadata.name
  iplist = node.split("-")
  ip = "."
  ip = ip.join(iplist[1:])
  if ip in nodetable:
    print(ip + " - Spot Instance Interruption received. Node will be drained and removed from the kubernetes cluster")
    drain = subprocess.Popen(["kubectl drain " + node + " --force --grace-period=0 --ignore-daemonsets --kubeconfig=" + kubeconfig], stdout=subprocess.PIPE, shell=True)
    (out, err) = drain.communicate()
    print("Drain node output:", out)
    api_instance.delete_node(node)
    slack_notify(channel_name, slack_token, ip)
  else:
    print("Node is not listed in Kubernetes Cluster")
