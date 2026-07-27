from EnterpriseCloudDiscovery.providers.azure.authentication_strategy import AzureCredentials
from EnterpriseCloudDiscovery.providers.azure.facade.base import AzureFacade
from EnterpriseCloudDiscovery.providers.azure.resources.aad.base import AAD
from EnterpriseCloudDiscovery.providers.azure.resources.rbac.base import RBAC
from EnterpriseCloudDiscovery.providers.azure.resources.keyvault.base import KeyVaults
from EnterpriseCloudDiscovery.providers.azure.resources.network.base import Networks
from EnterpriseCloudDiscovery.providers.azure.resources.securitycenter.base import SecurityCenter
from EnterpriseCloudDiscovery.providers.azure.resources.sqldatabase.base import Servers
from EnterpriseCloudDiscovery.providers.azure.resources.storageaccounts.base import StorageAccounts
from EnterpriseCloudDiscovery.providers.azure.resources.virtualmachines.base import VirtualMachines
from EnterpriseCloudDiscovery.providers.base.services import BaseServicesConfig
from EnterpriseCloudDiscovery.providers.azure.resources.appservice.base import AppServices
from EnterpriseCloudDiscovery.providers.azure.resources.mysqldatabase.base import MySQLServers
from EnterpriseCloudDiscovery.providers.azure.resources.postgresqldatabase.base import PostgreSQLServers
from EnterpriseCloudDiscovery.providers.azure.resources.loggingmonitoring.base import LoggingMonitoring

# Try to import proprietary services
try:
    from EnterpriseCloudDiscovery.providers.azure.resources.private_appgateway.base import ApplicationGateways
except ImportError:
    pass
try:
    from EnterpriseCloudDiscovery.providers.azure.resources.private_rediscache.base import RedisCaches
except ImportError:
    pass
try:
    from EnterpriseCloudDiscovery.providers.azure.resources.private_loadbalancer.base import LoadBalancers
except ImportError:
    pass


class AzureServicesConfig(BaseServicesConfig):

    def __init__(self,
                 credentials: AzureCredentials = None,
                 subscription_ids=[], all_subscriptions=None,
                 programmatic_execution=None,
                 **kwargs):

        super().__init__(credentials)

        facade = AzureFacade(credentials,
                             subscription_ids, all_subscriptions,
                             programmatic_execution)

        self.aad = AAD(facade)
        self.rbac = RBAC(facade)
        self.securitycenter = SecurityCenter(facade)
        self.sqldatabase = Servers(facade)
        self.storageaccounts = StorageAccounts(facade)
        self.keyvault = KeyVaults(facade)
        self.network = Networks(facade)
        self.virtualmachines = VirtualMachines(facade)
        self.appservice = AppServices(facade)
        self.mysqldatabase = MySQLServers(facade)
        self.postgresqldatabase = PostgreSQLServers(facade)
        self.loggingmonitoring = LoggingMonitoring(facade)

        # Instantiate proprietary services
        try:
            self.appgateway = ApplicationGateways(facade)
        except NameError as _:
            pass
        try:
            self.loadbalancer = LoadBalancers(facade)
        except NameError as _:
            pass
        try:
            self.rediscache = RedisCaches(facade)
        except NameError as _:
            pass

    def _is_provider(self, provider_name):
        return provider_name == 'azure'

    async def fetch(self, services: list, regions: list, excluded_regions: list):
        await super().fetch(services, regions, excluded_regions)

        # This is a unique case where we'll want to fetch additional resources (in the AAD service) in the
        # event the RBAC service was included. There's no existing cross-service fetching logic (only cross-service
        # processing), hence why we needed to add this.
        if 'rbac' in services and 'aad' in services:
            user_list = self.rbac.get_user_id_list()
            await self.aad.fetch_additional_users(user_list)
