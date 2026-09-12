# tf-module-azurerm-subnet-nsg

Terraform module: a network security group plus its subnet association,
driven by an ordered profile list and custom rules.

```hcl
module "subnet_nsg" {
  source   = "terraform.essinghigh.dev/essinghigh-org/subnet-nsg/azurerm"
  version  = "0.1.0"

  name                = "my-vnet-my-subnet-nsg"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = azurerm_subnet.this.id

  profiles = ["deny_all_inbound", "deny_all_outbound"]
  rules    = {}

  tags = var.tags
}
```

## Profile catalog

| Profile                   | Rules                                              | Priority |
| ------------------------- | -------------------------------------------------- | -------- |
| `allow_internet_outbound` | AllowInternetOutbound (`*` to `Internet`)          | 110      |
| `deny_internet_inbound`   | DenyInternetInbound (`Internet` to `*`)            | 4090     |
| `deny_all_inbound`        | DenyAllInbound (`*` to `*`)                        | 4096     |
| `deny_all_outbound`       | DenyAllOutbound (`*` to `*`)                       | 4096     |
| `deny_all`                | Both deny-all rules above                          | 4096     |

Priority bands are documented, not enforced: profile allows live at
100-999, custom rules read best at 1000-3999, profile backstops at
4000-4096. Azure evaluates the lowest priority number first per
direction, so an allow at 110 always beats a deny-all backstop at 4096.
The same priority in different directions is fine.

## Precedence and conflicts

1. Profiles expand in listed order. On a rule-name collision the later
   profile wins.
2. Custom `rules` override profile rules with the same name. Explicit
   always beats profile.
3. Plan-time preconditions reject: unknown profile names, directions
   other than Inbound/Outbound, access other than Allow/Deny, and two
   rules sharing a priority within the same direction.
4. The `deny_internet_inbound` profile additionally rejects inbound
   Allow rules sourced from the public Internet (`*`, `0.0.0.0/0`,
   `::/0`, `internet`), so the profile cannot be silently undermined.
5. Semantic overlap (an allow above a deny) resolves by Azure priority
   order. Keep allows in the low band and backstops at the top so the
   outcome reads off the plan.

## Notes

- `enabled = false` creates neither the group nor the association.
- Rule objects take full Azure fields: priority, direction, access,
  protocol, description, port ranges, address prefixes, and application
  security group IDs on both sides.
