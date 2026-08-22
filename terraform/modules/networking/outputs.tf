# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Publishes reusable values produced by the networking Terraform module.

# Output `vpc_id`: ID of the VPC that owns the resource.
output "vpc_id" {
  value = aws_vpc.this.id
}
# Output `public_subnet_ids`: Public subnet IDs used by internet-facing load-balancing or NAT resources.
output "public_subnet_ids" {
  value = [for s in aws_subnet.public : s.id]
}
# Output `app_subnet_ids`: Private application subnet IDs used by ECS workloads.
output "app_subnet_ids" {
  value = [for s in aws_subnet.app : s.id]
}
# Output `db_subnet_ids`: Private database subnet IDs used by PostgreSQL.
output "db_subnet_ids" {
  value = [for s in aws_subnet.db : s.id]
}
