from EnterpriseCloudDiscovery.providers.do.facade.base import DoFacade
from EnterpriseCloudDiscovery.providers.do.resources.base import DoCompositeResources
from EnterpriseCloudDiscovery.providers.do.resources.database.databases import Databases


class Databases(DoCompositeResources):
    _children = [(Databases, "databases")]

    def __init__(self, facade: DoFacade):
        super().__init__(facade)
        self.service = "database"

    async def fetch_all(self, **kwargs):
        await self._fetch_children(resource_parent=self)
