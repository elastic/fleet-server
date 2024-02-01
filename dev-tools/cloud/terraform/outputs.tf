output "stack_version" {
  value       = local.stack_version
  description = "Stack version"
}

output "elasticsearch_username" {
  value       = ec_deployment.deployment.elasticsearch_username
  sensitive   = true
  description = "The Elasticsearch username"
}

output "elasticsearch_password" {
  value       = ec_deployment.deployment.elasticsearch_password
  sensitive   = true
  description = "The Elasticsearch password"
}

output "elasticsearch_url" {
  value       = ec_deployment.deployment.elasticsearch.https_endpoint
  description = "The secure Elasticsearch URL"
}

output "kibana_url" {
  value       = ec_deployment.deployment.kibana.https_endpoint
  description = "The secure Kibana URL"
}

output "fleet_url" {
  value       = ec_deployment.deployment.integrations_server.endpoints.fleet
  description = "The secure Fleet URL"
}
