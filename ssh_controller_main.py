import json 
import boto3 
 
def lambda_handler(event, context): 
    ipranges = [] 
    with open('whitelist_ips.json') as json_file:   
        public_ips = json.load(json_file) 
    for ip in public_ips['SSHPermission']: 
        iprange = {} 
        iprange['CidrIp'] = ip['PublicIp'] 
        iprange['Description'] = ip['Username'] 
        ipranges.append(iprange) 
    print(ipranges) 
    client = boto3.resource('ec2') 
    security_group = client.SecurityGroup('sg-0632235b8ebd0749e') 
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
                        'GroupId': 'sg-0632235b8ebd0749e' 
                    } 
                ] 
            }, 
        ] 
    ) 
     
if __name__ == '__main__': 
    lambda_handler('', '') 
