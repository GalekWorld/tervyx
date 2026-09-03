locals {
  contract = {
    environment = var.environment
    network     = var.network
    compute     = var.compute
    postgres    = var.postgres
    redis       = var.redis
    secrets     = var.secrets
  }
}

# This provider-neutral resource is intentional: Tervyx does not yet select a
# cloud provider. It makes the mandatory security contract plan-visible and
# fails before any provider-specific module can be composed around it.
resource "terraform_data" "environment_security_contract" {
  input = local.contract

  lifecycle {
    precondition {
      condition     = var.network.gateway_public && var.network.api_private && var.network.worker_private
      error_message = "Only the gateway may be public; API and workers must remain private."
    }
    precondition {
      condition     = var.network.postgres_private && var.network.redis_private && var.network.egress_allowlist_only
      error_message = "Data services must be private and egress must be allowlist-only."
    }
    precondition {
      condition     = var.compute.api_replicas >= 1 && var.compute.worker_replicas >= 1 && var.compute.workload_identity && var.compute.read_only_filesystem && var.compute.drop_linux_caps
      error_message = "Compute requires workload identity, least privilege and hardened filesystem settings."
    }
    precondition {
      condition     = var.postgres.private_endpoint && var.postgres.tls_verify_full && var.postgres.encryption && var.postgres.backups_enabled && var.postgres.pitr_enabled
      error_message = "PostgreSQL requires private TLS, encryption, backups and PITR."
    }
    precondition {
      condition     = var.redis.private_endpoint && var.redis.tls_enabled && var.redis.encryption
      error_message = "Redis requires private TLS and encryption."
    }
    precondition {
      condition     = var.secrets.external_backend && var.secrets.workload_identity && var.secrets.rotation_enabled && startswith(var.secrets.secret_reference_prefix, "secret://")
      error_message = "Secrets must use external references, workload identity and rotation."
    }
    precondition {
      condition     = var.observability.private_collector && var.observability.audit_export && var.observability.metrics_restricted
      error_message = "Observability must use private collection, audit export and restricted metrics."
    }
    precondition {
      condition     = length(var.runtime_permissions.api_permissions) > 0 && length(var.runtime_permissions.worker_permissions) > 0 && length(var.runtime_permissions.migration_permissions) > 0
      error_message = "Each workload must declare a least-privilege permission set."
    }
  }
}

output "security_contract" {
  value       = terraform_data.environment_security_contract.output
  description = "Non-secret, plan-visible security posture for the selected environment."
}
