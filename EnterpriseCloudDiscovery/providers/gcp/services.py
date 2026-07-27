from EnterpriseCloudDiscovery.providers.base.services import BaseServicesConfig
from EnterpriseCloudDiscovery.providers.gcp.facade.base import GCPFacade
from EnterpriseCloudDiscovery.providers.gcp.resources.cloudsql.base import CloudSQL
from EnterpriseCloudDiscovery.providers.gcp.resources.memorystore.base import MemoryStore
from EnterpriseCloudDiscovery.providers.gcp.resources.cloudstorage.base import CloudStorage
from EnterpriseCloudDiscovery.providers.gcp.resources.gce.base import ComputeEngine
from EnterpriseCloudDiscovery.providers.gcp.resources.iam.base import IAM
from EnterpriseCloudDiscovery.providers.gcp.resources.kms.base import KMS
from EnterpriseCloudDiscovery.providers.gcp.resources.dns.base import DNS
from EnterpriseCloudDiscovery.providers.gcp.resources.functions.base import Functions
from EnterpriseCloudDiscovery.providers.gcp.resources.bigquery.base import BigQuery
from EnterpriseCloudDiscovery.providers.gcp.resources.stackdriverlogging.base import StackdriverLogging
from EnterpriseCloudDiscovery.providers.gcp.resources.stackdrivermonitoring.base import StackdriverMonitoring
from EnterpriseCloudDiscovery.providers.gcp.resources.gke.base import KubernetesEngine


class GCPServicesConfig(BaseServicesConfig):

    def __init__(self, credentials=None, default_project_id=None,
                 project_id=None, folder_id=None, organization_id=None, all_projects=None,
                 **kwargs):

        super().__init__(credentials)

        facade = GCPFacade(default_project_id, project_id, folder_id, organization_id, all_projects)

        self.cloudsql = CloudSQL(facade)
        self.cloudmemorystore = MemoryStore(facade)
        self.cloudstorage = CloudStorage(facade)
        self.computeengine = ComputeEngine(facade)
        self.functions = Functions(facade)
        self.bigquery = BigQuery(facade)
        self.iam = IAM(facade)
        self.kms = KMS(facade)
        self.stackdriverlogging = StackdriverLogging(facade)
        self.stackdrivermonitoring = StackdriverMonitoring(facade)
        self.kubernetesengine = KubernetesEngine(facade)
        self.dns = DNS(facade)

    def _is_provider(self, provider_name):
        return provider_name == 'gcp'
