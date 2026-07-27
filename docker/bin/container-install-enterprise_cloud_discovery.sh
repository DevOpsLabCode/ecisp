#!/bin/bash

# =====================================
# install EnterpriseCloudDiscovery into a virtual env
# =====================================

WORKDIR=/root
TMPDIR=/tmp

# =====================================
# install EnterpriseCloudDiscovery
# =====================================
cd ${WORKDIR}
virtualenv -p python3 enterprise_cloud_discovery
source ${WORKDIR}/enterprise_cloud_discovery/bin/activate
pip install enterprise_cloud_discovery

echo -e "\n\nEnterprise Cloud Discovery Engine Installation Complete!\n\n"
