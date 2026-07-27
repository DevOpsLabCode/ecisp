from EnterpriseCloudDiscovery.providers.do.facade.base import DoFacade
from EnterpriseCloudDiscovery.providers.do.resources.base import DoCompositeResources
from EnterpriseCloudDiscovery.providers.do.resources.spaces.buckets import Buckets


class Spaces(DoCompositeResources):
    _children = [(Buckets, "buckets")]

    def __init__(self, facade: DoFacade):
        super().__init__(facade)
        self.service = "buckets"

    async def fetch_all(self, **kwargs):
        await self._fetch_children(resource_parent=self)
