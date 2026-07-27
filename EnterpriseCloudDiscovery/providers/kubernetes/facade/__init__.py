from EnterpriseCloudDiscovery.providers.azure.facade.loggingmonitoring import LoggingMonitoringFacade
from EnterpriseCloudDiscovery.providers.gcp.facade.base import GCPFacade
from EnterpriseCloudDiscovery.providers.kubernetes.authentication_strategy import ClusterProvider, KubernetesCredentials
from EnterpriseCloudDiscovery.providers.kubernetes.facade.core import CoreFacade
from EnterpriseCloudDiscovery.providers.kubernetes.facade.eks import EKSFacade
from EnterpriseCloudDiscovery.providers.kubernetes.facade.extra import ExtraFacade
from EnterpriseCloudDiscovery.providers.kubernetes.facade.version import VersionFacade


class KubernetesFacade:
    def __init__(self, credentials: KubernetesCredentials):
        self.eks = None
        self.azure_monitoring = None
        self.gcp = None

        self.core = CoreFacade(credentials)
        self.extra = ExtraFacade(credentials)
        self.version = VersionFacade(credentials)

        if credentials.cluster_provider == ClusterProvider.AKS.value:
            self.azure_monitoring = LoggingMonitoringFacade(credentials)

        elif credentials.cluster_provider == ClusterProvider.EKS.value:
            self.eks = EKSFacade(credentials)

        elif credentials.cluster_provider == ClusterProvider.GKE.value:
            self.gcp = GCPFacade(credentials)
