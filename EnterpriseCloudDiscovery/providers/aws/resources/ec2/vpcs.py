from EnterpriseCloudDiscovery.providers.aws.resources.vpcs import Vpcs
from EnterpriseCloudDiscovery.providers.aws.resources.ec2.instances import EC2Instances
from EnterpriseCloudDiscovery.providers.aws.resources.ec2.securitygroups import SecurityGroups
from EnterpriseCloudDiscovery.providers.aws.resources.ec2.networkinterfaces import NetworkInterfaces


class Ec2Vpcs(Vpcs):
    _children = [
        (EC2Instances, 'instances'),
        (SecurityGroups, 'security_groups'),
        (NetworkInterfaces, 'network_interfaces')
    ]
