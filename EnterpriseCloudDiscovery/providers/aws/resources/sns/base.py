from EnterpriseCloudDiscovery.providers.aws.facade.base import AWSFacade
from EnterpriseCloudDiscovery.providers.aws.resources.regions import Regions

from .topics import Topics


class SNS(Regions):
    _children = [
        (Topics, 'topics')
    ]

    def __init__(self, facade: AWSFacade):
        super().__init__('sns', facade)
