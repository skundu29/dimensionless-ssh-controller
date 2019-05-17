import json
import boto3
import sys


def lambda_handler(sg):
    ipranges = []
    with open('whitelist_ips.json') as json_file:
        public_ips = json.load(json_file)
    for ip in public_ips['SSHPermission']:
        iprange = {'CidrIp': ip['PublicIp'], 'Description': ip['Username']}
        ipranges.append(iprange)
    print(ipranges)
    client = boto3.resource('ec2')
    security_group = client.SecurityGroup(sg)
    security_group.revoke_ingress(IpPermissions=security_group.ip_permissions)
    response = security_group.authorize_ingress(
        IpPermissions=[
            {
                'FromPort': 22,
                'IpProtocol': 'TCP',
                'IpRanges': ipranges,
                'ToPort': 22,
                'UserIdGroupPairs': [
                    {
                        'GroupId': sg
                    }
                ]
            },
        ]
    )
    return response


if __name__ == '__main__':
    sg = sys.argv[1]
    response = lambda_handler(sg)
    print(response)
