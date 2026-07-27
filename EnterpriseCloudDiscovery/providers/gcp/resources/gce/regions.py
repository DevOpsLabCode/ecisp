from EnterpriseCloudDiscovery.providers.gcp.resources.regions import Regions
from EnterpriseCloudDiscovery.providers.gcp.resources.gce.subnetworks import Subnetworks
from EnterpriseCloudDiscovery.providers.gcp.resources.gce.forwarding_rules import ForwardingRules


class GCERegions(Regions):
    _children = [
        (Subnetworks, 'subnetworks'),
        (ForwardingRules, "forwarding_rules"),
    ]
