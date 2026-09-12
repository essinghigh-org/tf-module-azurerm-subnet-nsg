output "id" {
  description = "ID of the network security group (null when disabled)."
  value       = var.enabled ? azurerm_network_security_group.this[0].id : null
}

output "name" {
  description = "Name of the network security group (null when disabled)."
  value       = var.enabled ? azurerm_network_security_group.this[0].name : null
}

output "rule_names" {
  description = "Names of the effective security rules, profiles plus custom."
  value       = sort(keys(local.effective_rules))
}
