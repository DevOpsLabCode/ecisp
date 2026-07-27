from EnterpriseCloudDiscovery.providers.gcp.resources.gce.instances import Instances
from EnterpriseCloudDiscovery.providers.gcp.resources.zones import Zones


class GCEZones(Zones):
    _children = [
        (Instances, 'instances'),
    ]
