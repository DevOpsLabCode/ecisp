from EnterpriseCloudDiscovery.providers.aws.resources.vpcs import Vpcs
from .load_balancers import LoadBalancers


class ELBv2Vpcs(Vpcs):
    _children = [
        (LoadBalancers, 'lbs'),
    ]
