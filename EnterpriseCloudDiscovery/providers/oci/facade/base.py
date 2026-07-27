from EnterpriseCloudDiscovery.providers.oci.facade.identity import IdentityFacade
from EnterpriseCloudDiscovery.providers.oci.facade.kms import KMSFacade
from EnterpriseCloudDiscovery.providers.oci.facade.objectstorage import ObjectStorageFacade
from EnterpriseCloudDiscovery.providers.oci.authentication_strategy import OracleCredentials


class OracleFacade:
    def __init__(self, credentials: OracleCredentials):
        self._credentials = credentials
        self._instantiate_facades()

    def _instantiate_facades(self):
        self.identity = IdentityFacade(self._credentials)
        self.kms = KMSFacade(self._credentials)
        self.objectstorage = ObjectStorageFacade(self._credentials)
