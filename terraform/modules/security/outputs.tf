# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Publishes reusable values produced by the security Terraform module.

# Output `alb_sg_id`: Identifier of the alb sg resource consumed by this module.
output "alb_sg_id" {
  value = aws_security_group.alb.id
}
# Output `app_sg_id`: Identifier of the app sg resource consumed by this module.
output "app_sg_id" {
  value = aws_security_group.app.id
}
# Output `db_sg_id`: Identifier of the db sg resource consumed by this module.
output "db_sg_id" {
  value = aws_security_group.db.id
}
