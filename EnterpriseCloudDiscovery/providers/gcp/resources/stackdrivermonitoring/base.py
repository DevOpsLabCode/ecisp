from EnterpriseCloudDiscovery.providers.gcp.resources.projects import Projects
from EnterpriseCloudDiscovery.providers.gcp.resources.stackdrivermonitoring.monitoring_alert_policies import MonitoringAlertPolicies
from EnterpriseCloudDiscovery.providers.gcp.resources.stackdrivermonitoring.uptime_checks import UptimeChecks
from EnterpriseCloudDiscovery.providers.gcp.resources.stackdrivermonitoring.alert_policies import AlertPolicies


class StackdriverMonitoring(Projects):
    _children = [ 
        (UptimeChecks, 'uptime_checks'),
        (AlertPolicies, 'alert_policies'),
        (MonitoringAlertPolicies, 'monitoring_alert_policies')
    ]
