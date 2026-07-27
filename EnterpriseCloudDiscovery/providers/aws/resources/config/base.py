from EnterpriseCloudDiscovery.providers.aws.facade.base import AWSFacade
from EnterpriseCloudDiscovery.providers.aws.resources.config.recorders import Recorders
from EnterpriseCloudDiscovery.providers.aws.resources.config.rules import Rules
from EnterpriseCloudDiscovery.providers.aws.resources.regions import Regions


class Config(Regions):
    _children = [
        (Recorders, 'recorders'),
        (Rules, 'rules')
    ]

    def __init__(self, facade: AWSFacade):
        super().__init__('config', facade)
