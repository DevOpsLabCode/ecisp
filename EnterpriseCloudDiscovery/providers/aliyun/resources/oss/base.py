from EnterpriseCloudDiscovery.providers.aliyun.resources.base import AliyunCompositeResources
from EnterpriseCloudDiscovery.providers.aliyun.resources.oss.buckets import Buckets


class OSS(AliyunCompositeResources):
    _children = [
        (Buckets, 'buckets')
    ]

    async def fetch_all(self, **kwargs):
        await self._fetch_children(resource_parent=self)
