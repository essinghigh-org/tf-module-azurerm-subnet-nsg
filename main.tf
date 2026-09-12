# --- Profile catalog -------------------------------------------------------
#
# Each profile expands to one or more fully-specified rules. Built-in
# priorities are chosen so profiles never collide with each other; only
# custom rules can collide, and those fail at plan time (see preconditions).
#
# Priority bands (documented, not enforced):
#   100-999    profile allows      (AllowInternetOutbound at 110)
#   1000-3999  custom rules        (pick what reads well)
#   4000-4096  profile backstops   (deny_internet_inbound at 4090, deny_alls at 4096)
#
# Azure evaluates the lowest priority number first per direction, so an
# allow at 110 always beats a deny-all backstop at 4096. Same priority in
# different directions is fine (Azure scopes uniqueness per direction).

locals {
  public_inbound_source_prefixes = toset([
    "*",
    "0.0.0.0/0",
    "::/0",
    "internet",
  ])

  allow_internet_outbound_rule = {
    priority                                   = 110
    direction                                  = "Outbound"
    access                                     = "Allow"
    protocol                                   = "*"
    description                                = "Allow outbound traffic to the public Internet."
    source_port_range                          = "*"
    source_port_ranges                         = null
    destination_port_range                     = "*"
    destination_port_ranges                    = null
    source_address_prefix                      = "*"
    source_address_prefixes                    = null
    destination_address_prefix                 = "Internet"
    destination_address_prefixes               = null
    source_application_security_group_ids      = null
    destination_application_security_group_ids = null
  }

  deny_internet_inbound_rule = {
    priority                                   = 4090
    direction                                  = "Inbound"
    access                                     = "Deny"
    protocol                                   = "*"
    description                                = "Deny inbound traffic from the public Internet."
    source_port_range                          = "*"
    source_port_ranges                         = null
    destination_port_range                     = "*"
    destination_port_ranges                    = null
    source_address_prefix                      = "Internet"
    source_address_prefixes                    = null
    destination_address_prefix                 = "*"
    destination_address_prefixes               = null
    source_application_security_group_ids      = null
    destination_application_security_group_ids = null
  }

  deny_all_inbound_rule = {
    priority                                   = 4096
    direction                                  = "Inbound"
    access                                     = "Deny"
    protocol                                   = "*"
    description                                = "Deny all inbound traffic."
    source_port_range                          = "*"
    source_port_ranges                         = null
    destination_port_range                     = "*"
    destination_port_ranges                    = null
    source_address_prefix                      = "*"
    source_address_prefixes                    = null
    destination_address_prefix                 = "*"
    destination_address_prefixes               = null
    source_application_security_group_ids      = null
    destination_application_security_group_ids = null
  }

  deny_all_outbound_rule = {
    priority                                   = 4096
    direction                                  = "Outbound"
    access                                     = "Deny"
    protocol                                   = "*"
    description                                = "Deny all outbound traffic."
    source_port_range                          = "*"
    source_port_ranges                         = null
    destination_port_range                     = "*"
    destination_port_ranges                    = null
    source_address_prefix                      = "*"
    source_address_prefixes                    = null
    destination_address_prefix                 = "*"
    destination_address_prefixes               = null
    source_application_security_group_ids      = null
    destination_application_security_group_ids = null
  }

  profile_catalog = {
    allow_internet_outbound = {
      AllowInternetOutbound = local.allow_internet_outbound_rule
    }
    deny_internet_inbound = {
      DenyInternetInbound = local.deny_internet_inbound_rule
    }
    deny_all_inbound = {
      DenyAllInbound = local.deny_all_inbound_rule
    }
    deny_all_outbound = {
      DenyAllOutbound = local.deny_all_outbound_rule
    }
    deny_all = {
      DenyAllInbound  = local.deny_all_inbound_rule
      DenyAllOutbound = local.deny_all_outbound_rule
    }
  }

  # Profiles expand in listed order: a later profile overrides an earlier
  # one on rule-name collision. Custom rules override everything.
  profile_rules = length(var.profiles) == 0 ? {} : merge([
    for profile in var.profiles : local.profile_catalog[profile]
    if contains(keys(local.profile_catalog), profile)
  ]...)

  effective_rules = merge(local.profile_rules, var.rules)
}

resource "azurerm_network_security_group" "this" {
  count = var.enabled ? 1 : 0

  name                = var.name
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  dynamic "security_rule" {
    for_each = local.effective_rules

    content {
      name                                       = security_rule.key
      priority                                   = security_rule.value.priority
      direction                                  = security_rule.value.direction
      access                                     = security_rule.value.access
      protocol                                   = security_rule.value.protocol
      description                                = security_rule.value.description
      source_port_range                          = security_rule.value.source_port_range
      source_port_ranges                         = security_rule.value.source_port_ranges
      destination_port_range                     = security_rule.value.destination_port_range
      destination_port_ranges                    = security_rule.value.destination_port_ranges
      source_address_prefix                      = security_rule.value.source_address_prefix
      source_address_prefixes                    = security_rule.value.source_address_prefixes
      source_application_security_group_ids      = security_rule.value.source_application_security_group_ids
      destination_address_prefix                 = security_rule.value.destination_address_prefix
      destination_address_prefixes               = security_rule.value.destination_address_prefixes
      destination_application_security_group_ids = security_rule.value.destination_application_security_group_ids
    }
  }

  lifecycle {
    precondition {
      condition     = alltrue([for profile in var.profiles : contains(keys(local.profile_catalog), profile)])
      error_message = "Unknown NSG profile. Must be one of: ${join(", ", sort(keys(local.profile_catalog)))}."
    }

    precondition {
      condition = alltrue([
        for rule in values(local.effective_rules) :
        contains(["inbound", "outbound"], lower(rule.direction))
      ])
      error_message = "Each NSG rule direction must be Inbound or Outbound."
    }

    precondition {
      condition = alltrue([
        for rule in values(local.effective_rules) :
        contains(["allow", "deny"], lower(rule.access))
      ])
      error_message = "Each NSG rule access must be Allow or Deny."
    }

    precondition {
      condition = length(distinct([
        for rule in values(local.effective_rules) : "${lower(rule.direction)}/${rule.priority}"
      ])) == length(local.effective_rules)
      error_message = "Each NSG rule must have a unique priority within its direction."
    }

    precondition {
      condition = !contains(var.profiles, "deny_internet_inbound") || alltrue([
        for rule in values(local.effective_rules) : !(
          lower(rule.direction) == "inbound" &&
          lower(rule.access) == "allow" &&
          (
            try(contains(local.public_inbound_source_prefixes, lower(trimspace(rule.source_address_prefix))), false) ||
            try(anytrue([
              for prefix in rule.source_address_prefixes : contains(local.public_inbound_source_prefixes, lower(trimspace(prefix)))
            ]), false)
          )
        )
      ])
      error_message = "The deny_internet_inbound profile cannot include public Internet inbound Allow rules."
    }
  }
}

resource "azurerm_subnet_network_security_group_association" "this" {
  count = var.enabled ? 1 : 0

  subnet_id                 = var.subnet_id
  network_security_group_id = azurerm_network_security_group.this[0].id
}
