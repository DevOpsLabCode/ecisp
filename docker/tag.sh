#!/bin/bash
source .env
#echo ${VERSION}
docker tag nccgroup/enterprise_cloud_discovery-aws:${VERSION} rossja/enterprise_cloud_discovery-aws:${VERSION}
docker tag nccgroup/enterprise_cloud_discovery-azure:${VERSION} rossja/enterprise_cloud_discovery-azure:${VERSION}
docker tag nccgroup/enterprise_cloud_discovery-gcp:${VERSION} rossja/enterprise_cloud_discovery-gcp:${VERSION}
docker tag nccgroup/enterprise_cloud_discovery-base:${VERSION} rossja/enterprise_cloud_discovery-base:${VERSION}

docker tag rossja/enterprise_cloud_discovery-aws:${VERSION} rossja/enterprise_cloud_discovery-aws:latest
docker tag rossja/enterprise_cloud_discovery-azure:${VERSION} rossja/enterprise_cloud_discovery-azure:latest
docker tag rossja/enterprise_cloud_discovery-gcp:${VERSION} rossja/enterprise_cloud_discovery-gcp:latest
docker tag rossja/enterprise_cloud_discovery-base:${VERSION} rossja/enterprise_cloud_discovery-base:latest

docker push rossja/enterprise_cloud_discovery-aws:${VERSION}
docker push rossja/enterprise_cloud_discovery-azure:${VERSION}
docker push rossja/enterprise_cloud_discovery-gcp:${VERSION}
docker push rossja/enterprise_cloud_discovery-base:${VERSION}

docker push rossja/enterprise_cloud_discovery-aws:latest
docker push rossja/enterprise_cloud_discovery-azure:latest
docker push rossja/enterprise_cloud_discovery-gcp:latest
docker push rossja/enterprise_cloud_discovery-base:latest
