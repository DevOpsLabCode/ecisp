#!/bin/sh

DIR="$( dirname "$_" )"
curl https://ip-ranges.amazonaws.com/ip-ranges.json > "$DIR/../EnterpriseCloudDiscovery/data/aws/ip-ranges/aws.json"
