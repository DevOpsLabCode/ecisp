import unittest
from EnterpriseCloudDiscovery.output.html import *
from EnterpriseCloudDiscovery.output.utils import *

#
# Test methods for EnterpriseCloudDiscovery/output
#
class TestScoutOutput(unittest.TestCase):

    ########################################
    # html.py
    ########################################

    def test_html_report(self):
        test_html = HTMLReport(report_name='test')
        assert (test_html.report_name == 'test')
        assert ('json' in test_html.get_content_from_folder(templates_type='conditionals'))
        assert ('json' in test_html.get_content_from_file(filename='/json_format.html'))

    def test_get_filename(self):
        assert ('enterprise_cloud_discovery-report/report.html' in get_filename("REPORT"))
        assert ('enterprise_cloud_discovery-report/enterprise_cloud_discovery-results/enterprise_cloud_discovery_results.js' in get_filename("RESULTS"))
        assert ('enterprise_cloud_discovery-results/enterprise_cloud_discovery_results.js' in get_filename("RESULTS", relative_path=True))
        assert ('enterprise_cloud_discovery-report/enterprise_cloud_discovery-results/enterprise_cloud_discovery_exceptions.js' in get_filename("EXCEPTIONS"))
        assert ('enterprise_cloud_discovery-results/enterprise_cloud_discovery_exceptions.js' in get_filename("EXCEPTIONS", relative_path=True))
        assert ('enterprise_cloud_discovery-report/enterprise_cloud_discovery-results/enterprise_cloud_discovery_errors.json' in get_filename("ERRORS"))
        assert ('enterprise_cloud_discovery-results/enterprise_cloud_discovery_errors.json' in get_filename("ERRORS", relative_path=True))
