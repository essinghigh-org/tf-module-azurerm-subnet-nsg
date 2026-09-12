variable "name" {
  description = "Name of the network security group."
  type        = string
}

variable "location" {
  description = "Azure region for the network security group."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group containing the network security group."
  type        = string
}

variable "subnet_id" {
  description = "ID of the subnet to associate the network security group with."
  type        = string
}

variable "enabled" {
  description = "Create the network security group and association. When false, neither is created."
  type        = bool
  default     = true
}

variable "profiles" {
  description = "Ordered list of rule profiles to apply. Later profiles win on rule-name collisions. See README for the catalog and precedence rules."
  type        = list(string)
  default     = []
}

variable "rules" {
  description = "Custom security rules keyed by rule name. A custom rule overrides a profile rule with the same name."
  type = map(object({
    priority                                   = number
    direction                                  = string
    access                                     = string
    protocol                                   = optional(string, "*")
    description                                = optional(string)
    source_port_range                          = optional(string)
    source_port_ranges                         = optional(list(string))
    destination_port_range                     = optional(string)
    destination_port_ranges                    = optional(list(string))
    source_address_prefix                      = optional(string)
    source_address_prefixes                    = optional(list(string))
    source_application_security_group_ids      = optional(list(string))
    destination_address_prefix                 = optional(string)
    destination_address_prefixes               = optional(list(string))
    destination_application_security_group_ids = optional(list(string))
  }))
  default  = {}
  nullable = false
}

variable "tags" {
  description = "Tags applied to the network security group."
  type        = map(string)
  default     = {}
  nullable    = false
}
