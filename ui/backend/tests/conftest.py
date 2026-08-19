"""
Installs a fake EnterpriseCloudDiscovery package into sys.modules before any
`app.*` module is imported, so the test suite exercises the "engine
available" code paths in app/engine_runner.py without needing the real
engine (and its many cloud SDK dependencies) installed.

Import order matters: pytest imports conftest.py before collecting test
modules, and Python's import system checks sys.modules before touching the
filesystem/sys.path, so these fakes win even though the real
EnterpriseCloudDiscovery package also exists two directories up.
"""
import asyncio
import sys
import types


def _stub_run(**kwargs):
    # Mirrors the real engine's __main__.run(): it calls
    # asyncio.get_event_loop() directly and expects the calling thread to
    # already have one. Python 3.10+ raises RuntimeError instead of
    # implicitly creating one for non-main threads, which is exactly the
    # bug this stub exists to catch -- see JobManager._run_worker.
    loop = asyncio.get_event_loop()
    if loop.is_closed():
        loop = asyncio.new_event_loop()
    loop.close()
    return 0


def _install_stub_engine() -> None:
    if "EnterpriseCloudDiscovery" in sys.modules:
        return

    package = types.ModuleType("EnterpriseCloudDiscovery")
    package.__path__ = []  # mark as a package

    main_module = types.ModuleType("EnterpriseCloudDiscovery.__main__")
    main_module.run = _stub_run  # overridden per-test via monkeypatch

    output_package = types.ModuleType("EnterpriseCloudDiscovery.output")
    output_package.__path__ = []

    encoder_module = types.ModuleType("EnterpriseCloudDiscovery.output.result_encoder")

    class _StubJavaScriptEncoder:
        def __init__(self, report_name=None, report_dir=None):
            self.report_name = report_name
            self.report_dir = report_dir

        def load_from_file(self, file_type):
            return {"provider_code": "stub", "services": {}}

    encoder_module.JavaScriptEncoder = _StubJavaScriptEncoder

    sys.modules["EnterpriseCloudDiscovery"] = package
    sys.modules["EnterpriseCloudDiscovery.__main__"] = main_module
    sys.modules["EnterpriseCloudDiscovery.output"] = output_package
    sys.modules["EnterpriseCloudDiscovery.output.result_encoder"] = encoder_module


_install_stub_engine()
