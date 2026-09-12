mock_provider "azurerm" {
  mock_resource "azurerm_network_security_group" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Network/networkSecurityGroups/test-nsg"
    }
  }
}

variables {
  name                = "test-nsg"
  location            = "uksouth"
  resource_group_name = "rg-test"
  subnet_id           = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Network/virtualNetworks/test/subnets/test"
}

run "deny_all_expands_to_both_directions" {
  command = plan

  variables {
    profiles = ["deny_all"]
  }

  assert {
    condition     = output.rule_names == tolist(["DenyAllInbound", "DenyAllOutbound"])
    error_message = "deny_all should expand to both deny rules"
  }
}

run "custom_rule_overrides_profile_on_name_clash" {
  command = plan

  variables {
    profiles = ["deny_all_inbound"]
    rules = {
      DenyAllInbound = {
        priority  = 3000
        direction = "Inbound"
        access    = "Deny"
      }
    }
  }

  assert {
    condition     = output.rule_names == tolist(["DenyAllInbound"])
    error_message = "custom rule should replace the profile rule of the same name"
  }

  assert {
    condition     = output.rules["DenyAllInbound"].priority == 3000
    error_message = "the custom rule priority should win over the profile priority"
  }
}

run "duplicate_priority_same_direction_fails" {
  command = plan

  variables {
    profiles = ["deny_all_inbound"]
    rules = {
      Clash = {
        priority  = 4096
        direction = "Inbound"
        access    = "Allow"
      }
    }
  }

  expect_failures = [azurerm_network_security_group.this]
}

run "same_priority_different_direction_passes" {
  command = plan

  variables {
    profiles = ["deny_all"]
  }

  assert {
    condition     = length(output.rule_names) == 2
    error_message = "4096 in both directions must be accepted"
  }
}

run "unknown_profile_fails" {
  command = plan

  variables {
    profiles = ["deny_everything_forever"]
  }

  expect_failures = [azurerm_network_security_group.this]
}

run "deny_internet_inbound_rejects_public_allow" {
  command = plan

  variables {
    profiles = ["deny_internet_inbound"]
    rules = {
      Oops = {
        priority              = 100
        direction             = "Inbound"
        access                = "Allow"
        source_address_prefix = "Internet"
      }
    }
  }

  expect_failures = [azurerm_network_security_group.this]
}

run "deny_internet_inbound_allows_scoped_allow" {
  command = plan

  variables {
    profiles = ["deny_internet_inbound"]
    rules = {
      Scoped = {
        priority              = 100
        direction             = "Inbound"
        access                = "Allow"
        source_address_prefix = "10.0.0.0/8"
      }
    }
  }

  assert {
    condition     = contains(output.rule_names, "Scoped")
    error_message = "scoped inbound Allow rules must be accepted alongside the profile"
  }
}
