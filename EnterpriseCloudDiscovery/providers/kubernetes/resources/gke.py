from EnterpriseCloudDiscovery.providers.gcp.resources.gke.clusters import Clusters
from EnterpriseCloudDiscovery.providers.gcp.resources.projects import Projects


class GKE(Projects):
    _children = [
        (Clusters, 'clusters')
    ]