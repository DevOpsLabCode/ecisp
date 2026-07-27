import subprocess
import unittest
from unittest import mock

import pytest
from EnterpriseCloudDiscovery.__main__ import run_from_cli
from EnterpriseCloudDiscovery.core.console import set_logger_configuration


class TestEnterpriseCloudDiscoveryClass(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        set_logger_configuration(is_debug=True)
        cls.has_run_scout_suite = False

    @pytest.mark.xfail("only runs with AWS, cannot be used dynamically")
    @staticmethod
    def call_scout_suite(args):
        args = ['./enterprise-cloud-discovery.py'] + args

        args.append('aws')

        if TestEnterpriseCloudDiscoveryClass.profile_name:
            args.append('--profile')
            args.append(TestEnterpriseCloudDiscoveryClass.profile_name)
        # TODO: FIXME this only tests AWS

        args.append('--force')
        args.append('--debug')
        args.append('--no-browser')
        if TestEnterpriseCloudDiscoveryClass.has_run_scout_suite:
            args.append('--local')
        TestEnterpriseCloudDiscoveryClass.has_run_scout_suite = True

        sys = None
        with mock.patch.object(sys, 'argv', args):
            return run_from_cli()

    def test_scout_suite_help(self):
        """Make sure that EnterpriseCloudDiscovery does not crash with --help"""
        command = './enterprise-cloud-discovery.py --help'
        process = subprocess.Popen(command, shell=True, stdout=None)
        process.wait()
        assert process.returncode == 0

    @pytest.mark.xfail
    def test_scout_suite_default_run(self):
        """Make sure that EnterpriseCloudDiscovery's default run does not crash"""
        rc = self.call_scout_suite([])
        assert (rc == 0)
