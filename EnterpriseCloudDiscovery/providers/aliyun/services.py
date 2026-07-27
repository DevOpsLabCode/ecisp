from EnterpriseCloudDiscovery.providers.aliyun.facade.base import AliyunFacade
from EnterpriseCloudDiscovery.providers.base.services import BaseServicesConfig
from EnterpriseCloudDiscovery.providers.aliyun.resources.ram.base import RAM
from EnterpriseCloudDiscovery.providers.aliyun.resources.actiontrail.base import ActionTrail
from EnterpriseCloudDiscovery.providers.aliyun.resources.vpc.base import VPC
from EnterpriseCloudDiscovery.providers.aliyun.resources.ecs.base import ECS
from EnterpriseCloudDiscovery.providers.aliyun.resources.rds.base import RDS
from EnterpriseCloudDiscovery.providers.aliyun.resources.kms.base import KMS
from EnterpriseCloudDiscovery.providers.aliyun.resources.oss.base import OSS



class AliyunServicesConfig(BaseServicesConfig):
    def __init__(self, credentials, **kwargs):
        super().__init__(credentials)

        facade = AliyunFacade(credentials)

        self.actiontrail = ActionTrail(facade)
        self.ram = RAM(facade)
        self.ecs = ECS(facade)
        self.rds = RDS(facade)
        self.vpc = VPC(facade)
        self.kms = KMS(facade)
        self.oss = OSS(facade)

    def _is_provider(self, provider_name):
        return provider_name == 'aliyun'
