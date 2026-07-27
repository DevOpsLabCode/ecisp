from EnterpriseCloudDiscovery.providers.aws.resources.vpcs import Vpcs
from .load_balancers import LoadBalancers


class ELBVpcs(Vpcs):
    _children = [
        (LoadBalancers, 'elbs'),
    ]
