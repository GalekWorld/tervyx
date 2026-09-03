variable "environment" {
  type        = string
  description = "Strictly isolated deployment environment."

  validation {
    condition     = contains(["staging", "production"], var.environment)
    error_message = "Only staging and production are supported by this contract."
  }
}

variable "network" {
  type = object({
    gateway_public        = bool
    api_private           = bool
    worker_private        = bool
    postgres_private      = bool
    redis_private         = bool
    egress_allowlist_only = bool
  })
}

variable "compute" {
  type = object({
    api_replicas         = number
    worker_replicas      = number
    workload_identity    = bool
    read_only_filesystem = bool
    drop_linux_caps      = bool
  })
}

variable "postgres" {
  type = object({
    private_endpoint = bool
    tls_verify_full  = bool
    encryption       = bool
    backups_enabled  = bool
    pitr_enabled     = bool
  })
}

variable "redis" {
  type = object({
    private_endpoint = bool
    tls_enabled      = bool
    encryption       = bool
  })
}

variable "secrets" {
  type = object({
    external_backend        = bool
    workload_identity       = bool
    rotation_enabled        = bool
    secret_reference_prefix = string
  })
}

variable "observability" {
  type = object({
    private_collector = bool
    audit_export      = bool
    metrics_restricted = bool
  })
}

variable "runtime_permissions" {
  type = object({
    api_permissions       = set(string)
    worker_permissions    = set(string)
    migration_permissions = set(string)
  })
}
