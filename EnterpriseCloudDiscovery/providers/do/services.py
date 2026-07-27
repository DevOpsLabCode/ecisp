from EnterpriseCloudDiscovery.providers.do.authentication_strategy import DoCredentials
from EnterpriseCloudDiscovery.providers.do.resources.droplet.base import Droplets
from EnterpriseCloudDiscovery.providers.do.resources.spaces.base import Spaces
from EnterpriseCloudDiscovery.providers.do.resources.networking.base import Networking
from EnterpriseCloudDiscovery.providers.do.resources.database.base import Databases
from EnterpriseCloudDiscovery.providers.do.resources.kubernetes.base import Kubernetes
from EnterpriseCloudDiscovery.providers.do.facade.base import DoFacade
from EnterpriseCloudDiscovery.providers.base.services import BaseServicesConfig


class DigitalOceanServicesConfig(BaseServicesConfig):
    def __init__(self, credentials: DoCredentials = None, **kwargs):
        super().__init__(credentials)

        facade = DoFacade(credentials)

        self.droplet = Droplets(facade)
        self.networking = Networking(facade)
        self.database = Databases(facade)
        self.kubernetes = Kubernetes(facade)
        if self.credentials.session:
            self.spaces = Spaces(facade)

    def _is_provider(self, provider_name):
        return provider_name == "do"
