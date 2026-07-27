from EnterpriseCloudDiscovery.providers.gcp.resources.projects import Projects
from EnterpriseCloudDiscovery.providers.gcp.resources.stackdriverlogging.logging_metrics import LoggingMetrics
from EnterpriseCloudDiscovery.providers.gcp.resources.stackdriverlogging.sinks import Sinks
from EnterpriseCloudDiscovery.providers.gcp.resources.stackdriverlogging.metrics import Metrics


class StackdriverLogging(Projects):
    _children = [ 
        (Sinks, 'sinks'),
        (Metrics, 'metrics'),
        (LoggingMetrics, 'logging_metrics')
    ]
