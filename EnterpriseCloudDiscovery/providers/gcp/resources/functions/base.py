from EnterpriseCloudDiscovery.providers.gcp.resources.functions.functions_v1 import FunctionsV1
from EnterpriseCloudDiscovery.providers.gcp.resources.functions.functions_v2 import FunctionsV2
from EnterpriseCloudDiscovery.providers.gcp.resources.projects import Projects

class Functions(Projects):
    _children = [
        (FunctionsV1, 'functions_v1'),
        (FunctionsV2, 'functions_v2')
    ]
