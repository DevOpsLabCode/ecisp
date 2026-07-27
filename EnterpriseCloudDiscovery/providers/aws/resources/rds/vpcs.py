from EnterpriseCloudDiscovery.providers.aws.resources.vpcs import Vpcs
from EnterpriseCloudDiscovery.providers.aws.resources.rds.instances import RDSInstances
from EnterpriseCloudDiscovery.providers.aws.resources.rds.snapshots import Snapshots
from EnterpriseCloudDiscovery.providers.aws.resources.rds.subnetgroups import SubnetGroups


class RDSVpcs(Vpcs):
    _children = [
        (RDSInstances, 'instances'),
        (Snapshots, 'snapshots'),
        (SubnetGroups, 'subnet_groups'),
    ]
