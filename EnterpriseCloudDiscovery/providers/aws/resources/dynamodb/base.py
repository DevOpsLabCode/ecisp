from EnterpriseCloudDiscovery.providers.aws.facade.base import AWSFacade
from EnterpriseCloudDiscovery.providers.aws.resources.regions import Regions
from .tables import Tables


class DynamoDB(Regions):
    _children = [
        (Tables, 'tables')
    ]

    def __init__(self, facade: AWSFacade):
        super(DynamoDB, self).__init__('dynamodb', facade)
