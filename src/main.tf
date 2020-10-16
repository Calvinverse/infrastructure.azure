terraform {
    backend "local" {
    }
}

provider "azurerm" {
  alias  = "production"

  features {}

  subscription_id = var.subscription_production

  version = "~>2.21.0"
}

provider "azurerm" {
    #alias = "target"

    features {}

    subscription_id = var.environment == "production" ? var.subscription_production : var.subscription_test

    version = "~>2.21.0"
}

provider "azuread" {
  version = "=0.11.0"

  subscription_id = var.environment == "production" ? var.subscription_production : var.subscription_test
}


#
# LOCALS
#

locals {
    location_map = {
        australiacentral = "auc",
        australiacentral2 = "auc2",
        australiaeast = "aue",
        australiasoutheast = "ause",
        brazilsouth = "brs",
        canadacentral = "cac",
        canadaeast = "cae",
        centralindia = "inc",
        centralus = "usc",
        eastasia = "ase",
        eastus = "use",
        eastus2 = "use2",
        francecentral = "frc",
        francesouth = "frs",
        germanynorth = "den",
        germanywestcentral = "dewc",
        japaneast = "jpe",
        japanwest = "jpw",
        koreacentral = "krc",
        koreasouth = "kre",
        northcentralus = "usnc",
        northeurope = "eun",
        norwayeast = "noe",
        norwaywest = "now",
        southafricanorth = "zan",
        southafricawest = "zaw",
        southcentralus = "ussc",
        southeastasia = "asse",
        southindia = "ins",
        switzerlandnorth = "chn",
        switzerlandwest = "chw",
        uaecentral = "aec",
        uaenorth = "aen",
        uksouth = "uks",
        ukwest = "ukw",
        westcentralus = "uswc",
        westeurope = "euw",
        westindia = "inw",
        westus = "usw",
        westus2 = "usw2",
    }
}

locals {
    environment_short = substr(var.environment, 0, 1)
    location_short = lookup(local.location_map, var.location, "aue")
}

# Name prefixes
locals {
    name_prefix = "${local.environment_short}-${local.location_short}"
    name_prefix_tf = "${local.name_prefix}-tf-${var.category}-${var.spoke_id}"
}

locals {
    common_tags = {
        category    = "${var.category}"
        environment = "${var.environment}"
        location    = "${var.location}"
        source  = "${var.meta_source}"
        spoke_id = "${var.spoke_id}"
        version = "${var.meta_version}"
    }

    extra_tags = {
    }
}

# Network security rules
locals {
    default_nsg_rule = {
        direction                                  = "Inbound"
        access                                     = "Allow"
        protocol                                   = "Tcp"
        description                                = null
        source_port_range                          = null
        source_port_ranges                         = null
        destination_port_range                     = null
        destination_port_ranges                    = null
        source_address_prefix                      = null
        source_address_prefixes                    = null
        source_application_security_group_ids      = null
        destination_address_prefix                 = null
        destination_address_prefixes               = null
        destination_application_security_group_ids = null
    }
    default_nsg_rules = [
        # SSH
        {
            access = "Allow"
            destination_address_prefix = "VirtualNetwork"
            destination_port_range = "22"
            direction = "Inbound"
            name = "ssh"
            protocol = "Tcp"
            source_address_prefix = "VirtualNetwork"
            source_port_range = "*"
        },

        # CONSUL
        {
            access = "Allow"
            destination_address_prefix = "VirtualNetwork"
            destination_port_range = "8300"
            direction = "Inbound"
            name = "consul-rpc"
            protocol = "Tcp"
            source_address_prefix = "VirtualNetwork"
            source_port_range = "*"
        },
        {
            access = "Allow"
            destination_address_prefix = "VirtualNetwork"
            destination_port_range = "8301"
            direction = "Inbound"
            name = "consul-serf-lan-tcp"
            protocol = "Tcp"
            source_address_prefix = "VirtualNetwork"
            source_port_range = "*"
        },
        {
            access = "Allow"
            destination_address_prefix = "VirtualNetwork"
            destination_port_range = "8301"
            direction = "Inbound"
            name = "consul-serf-lan-udp"
            protocol = "Udp"
            source_address_prefix = "VirtualNetwork"
            source_port_range = "*"
        },
        {
            access = "Allow"
            destination_address_prefix = "VirtualNetwork"
            destination_port_range = "8302"
            direction = "Inbound"
            name = "consul-serf-wan-tcp"
            protocol = "Tcp"
            source_address_prefix = "VirtualNetwork"
            source_port_range = "*"
        },
        {
            access = "Allow"
            destination_address_prefix = "VirtualNetwork"
            destination_port_range = "8302"
            direction = "Inbound"
            name = "consul-serf-wan-udp"
            protocol = "Udp"
            source_address_prefix = "VirtualNetwork"
            source_port_range = "*"
        },
        {
            access = "Allow"
            destination_address_prefix = "VirtualNetwork"
            destination_port_range = "8500"
            direction = "Inbound"
            name = "consul-http"
            protocol = "Tcp"
            source_address_prefix = "VirtualNetwork"
            source_port_range = "*"
        },
        {
            access = "Allow"
            destination_address_prefix = "VirtualNetwork"
            destination_port_range = "8600"
            direction = "Inbound"
            name = "consul-dns"
            protocol = "Tcp"
            source_address_prefix = "VirtualNetwork"
            source_port_range = "*"
        },
    ]

    merged_nsg_rules = flatten([
        for nsg in local.default_nsg_rules : merge(local.default_nsg_rule, nsg)
    ])
}

# Diagnostics
locals {
    diag_vnet_logs = [
        "VMProtectionAlerts",
    ]
    diag_vnet_metrics = [
        "AllMetrics",
    ]
    diag_nsg_logs = [
        "NetworkSecurityGroupEvent",
        "NetworkSecurityGroupRuleCounter",
    ]
    diag_pip_logs = [
        "DDoSProtectionNotifications",
        "DDoSMitigationFlowLogs",
        "DDoSMitigationReports",
    ]
    diag_pip_metrics = [
        "AllMetrics",
    ]
    diag_fw_logs = [
        "AzureFirewallApplicationRule",
        "AzureFirewallNetworkRule",
    ]
    diag_fw_metrics = [
        "AllMetrics",
    ]

    diag_all_logs = setunion(
        local.diag_vnet_logs,
        local.diag_nsg_logs,
        local.diag_pip_logs,
    local.diag_fw_logs)
    diag_all_metrics = setunion(
        local.diag_vnet_metrics,
        local.diag_pip_metrics,
    local.diag_fw_metrics)

    parsed_diag = {
        log_analytics_id   = "e1c46677-b6e1-4c5a-8983-bfecd30e5061"
        metric             = local.diag_all_metrics
        log                = local.diag_all_logs
        }
}

data "azurerm_client_config" "current" {}

locals {
    network_watcher_name = "NetworkWatcher_${var.location}"
    network_watcher_resource_group = "NetworkWatcherRG"

    hub_resource_group = "p-aue-tf-nwk-hub-rg"
    hub_dns_zone_name = "hub.azure.calvinverse.net"
    hub_virtual_network = "p-aue-tf-nwk-hub-vn"
}

data "azurerm_log_analytics_workspace" "log_analytics_workspace" {
    name   = "p-aue-tf-analytics-law-logs"
    provider = azurerm.production
    resource_group_name = "p-aue-tf-analytics-rg"
}

data "azurerm_virtual_network" "hub" {
    name = local.hub_virtual_network
    provider = azurerm.production
    resource_group_name = local.hub_resource_group
}

data "azurerm_subscription" "target" {
    subscription_id = var.environment == "production" ? var.subscription_production : var.subscription_test
}

#
# Resource group
#

resource "azurerm_resource_group" "rg" {
    location = var.location
    name = "${local.name_prefix_tf}-rg"

    tags = merge( local.common_tags, local.extra_tags, var.tags )
}

#
# Key Vault
#

resource "azurerm_key_vault" "keys" {
    enabled_for_deployment  = true
    enabled_for_disk_encryption = true
    location  = var.location
    name  = "${local.name_prefix_tf}-kv"
    purge_protection_enabled    = false
    resource_group_name = azurerm_resource_group.rg.name
    sku_name = "standard"
    soft_delete_enabled = false
    tenant_id = data.azurerm_client_config.current.tenant_id

    access_policy {
        tenant_id = data.azurerm_client_config.current.tenant_id
        object_id = data.azurerm_client_config.current.object_id

        certificate_permissions = [
            "backup",
            "create",
            "delete",
            "deleteissuers",
            "get",
            "getissuers",
            "import",
            "list",
            "listissuers",
            "managecontacts",
            "manageissuers",
            "purge",
            "recover",
            "restore",
            "setissuers",
            "update",
        ]

            key_permissions = [
            "backup",
            "create",
            "decrypt",
            "delete",
            "encrypt",
            "get",
            "import",
            "list",
            "purge",
            "recover",
            "restore",
            "sign",
            "unwrapKey",
            "update",
            "verify",
            "wrapKey"
        ]

            secret_permissions = [
            "backup",
            "delete",
            "get",
            "list",
            "purge",
            "recover",
            "restore",
            "set"
        ]

            storage_permissions = [
            "backup",
            "delete",
            "deletesas",
            "get",
            "getsas",
            "list",
            "listsas",
            "purge",
            "recover",
            "regeneratekey",
            "restore",
            "set",
            "setsas",
            "update"
        ]
    }

    tags = merge( local.common_tags, local.extra_tags, var.tags )
}

# key vault to store certificates and consul tokens
resource "azurerm_key_vault" "infrastructure" {
    enabled_for_deployment  = true
    enabled_for_disk_encryption = true
    location  = var.location
    name  = "${local.name_prefix_tf}-kv-infra"
    purge_protection_enabled    = false
    resource_group_name = azurerm_resource_group.rg.name
    sku_name = "standard"
    soft_delete_enabled = false
    tenant_id = data.azurerm_client_config.current.tenant_id

    access_policy {
        tenant_id = data.azurerm_client_config.current.tenant_id
        object_id = data.azurerm_client_config.current.object_id

        certificate_permissions = [
            "backup",
            "create",
            "delete",
            "deleteissuers",
            "get",
            "getissuers",
            "import",
            "list",
            "listissuers",
            "managecontacts",
            "manageissuers",
            "purge",
            "recover",
            "restore",
            "setissuers",
            "update",
        ]

            key_permissions = [
            "backup",
            "create",
            "decrypt",
            "delete",
            "encrypt",
            "get",
            "import",
            "list",
            "purge",
            "recover",
            "restore",
            "sign",
            "unwrapKey",
            "update",
            "verify",
            "wrapKey"
        ]

            secret_permissions = [
            "backup",
            "delete",
            "get",
            "list",
            "purge",
            "recover",
            "restore",
            "set"
        ]

            storage_permissions = [
            "backup",
            "delete",
            "deletesas",
            "get",
            "getsas",
            "list",
            "listsas",
            "purge",
            "recover",
            "regeneratekey",
            "restore",
            "set",
            "setsas",
            "update"
        ]
    }

    tags = merge( local.common_tags, local.extra_tags, var.tags )
}

#
# Storage account for flow logs
#

resource "azurerm_storage_account" "storage" {
    access_tier  = "Hot"
    account_kind = "StorageV2"
    account_replication_type  = "LRS"
    account_tier = "Standard"
    enable_https_traffic_only = true
    location = var.location
    name    = lower(replace("${local.name_prefix_tf}st", "/[[:^alnum:]]/", ""))
    resource_group_name   = azurerm_resource_group.rg.name
    tags = merge( local.common_tags, local.extra_tags, var.tags )
}

resource "azurerm_advanced_threat_protection" "threat_protection" {
    enabled   = true
    target_resource_id = azurerm_storage_account.storage.id
}

#
# Spoke network with subnets
#

resource "azurerm_virtual_network" "vnet" {
    address_space = [ var.address_space ]
    location = var.location
    name  = "${local.name_prefix_tf}-vn"
    resource_group_name = azurerm_resource_group.rg.name

    tags = merge( local.common_tags, local.extra_tags, var.tags )
}

resource "azurerm_monitor_diagnostic_setting" "vnet" {
    count    = 1
    name = "${local.name_prefix_tf}-mds-vnet"
    target_resource_id    = azurerm_virtual_network.vnet.id
    log_analytics_workspace_id = data.azurerm_log_analytics_workspace.log_analytics_workspace.id

    dynamic "log" {
        for_each = setintersection(local.parsed_diag.log, local.diag_vnet_logs)
        content {
    category = log.value

    retention_policy {
        enabled = false
    }
        }
    }

    dynamic "metric" {
        for_each = setintersection(local.parsed_diag.metric, local.diag_vnet_metrics)
        content {
    category = metric.value

    retention_policy {
        enabled = false
    }
        }
    }
}

#
# Spoke subnets
#

resource "azurerm_subnet" "vnet" {
    address_prefixes = [ cidrsubnet(var.address_space, 0, 0) ]
    name = "${local.name_prefix_tf}-sn"
    resource_group_name = azurerm_resource_group.rg.name
    virtual_network_name = azurerm_virtual_network.vnet.name

    service_endpoints = [
        "Microsoft.ContainerRegistry",
        "Microsoft.KeyVault",
        "Microsoft.Storage",
    ]
}

#
# Route table
#

resource "azurerm_route_table" "out" {
    name = "${local.name_prefix_tf}-rt-outbound"
    location = azurerm_resource_group.rg.location
    resource_group_name = azurerm_resource_group.rg.name

    tags = merge( local.common_tags, local.extra_tags, var.tags )
}

resource "azurerm_subnet_route_table_association" "vnet" {
    subnet_id  = azurerm_subnet.vnet.id
    route_table_id = azurerm_route_table.out.id
}

#
# Network Security Groups
#

resource "azurerm_network_security_group" "vnet" {
    name   = "${local.name_prefix_tf}-nsg-sn"
    location   = azurerm_resource_group.rg.location
    resource_group_name = azurerm_resource_group.rg.name

    tags = merge( local.common_tags, local.extra_tags, var.tags )
}

resource "azurerm_network_watcher_flow_log" "vnet" {
    enabled = true
    network_security_group_id = azurerm_network_security_group.vnet.id
    network_watcher_name = local.network_watcher_name
    resource_group_name = local.network_watcher_resource_group
    storage_account_id = azurerm_storage_account.storage.id

    retention_policy {
        enabled = true
        days    = 7
    }

    traffic_analytics {
        enabled               = true
        workspace_id          = data.azurerm_log_analytics_workspace.log_analytics_workspace.workspace_id
        workspace_region      = var.location
        workspace_resource_id = data.azurerm_log_analytics_workspace.log_analytics_workspace.id
        interval_in_minutes   = 10
    }
}

resource "azurerm_network_security_rule" "vnet" {
    access = local.merged_nsg_rules[count.index].access
    count = length(local.merged_nsg_rules)

    description = local.merged_nsg_rules[count.index].description

    destination_address_prefix = local.merged_nsg_rules[count.index].destination_address_prefix
    destination_address_prefixes = local.merged_nsg_rules[count.index].destination_address_prefixes
    destination_application_security_group_ids = local.merged_nsg_rules[count.index].destination_application_security_group_ids
    destination_port_range = local.merged_nsg_rules[count.index].destination_port_range
    destination_port_ranges = local.merged_nsg_rules[count.index].destination_port_ranges

    direction = local.merged_nsg_rules[count.index].direction
    name = local.merged_nsg_rules[count.index].name
    network_security_group_name = azurerm_network_security_group.vnet.name
    priority = 100 + 100 * count.index
    protocol = local.merged_nsg_rules[count.index].protocol
    resource_group_name = azurerm_resource_group.rg.name

    source_address_prefix = local.merged_nsg_rules[count.index].source_address_prefix
    source_address_prefixes = local.merged_nsg_rules[count.index].source_address_prefixes
    source_application_security_group_ids = local.merged_nsg_rules[count.index].source_application_security_group_ids
    source_port_range = local.merged_nsg_rules[count.index].source_port_range
    source_port_ranges = local.merged_nsg_rules[count.index].source_port_ranges
}

resource "azurerm_monitor_diagnostic_setting" "nsg" {
    log_analytics_workspace_id = data.azurerm_log_analytics_workspace.log_analytics_workspace.id
    name = "${local.name_prefix_tf}-mds-nsg"
    target_resource_id = azurerm_network_security_group.vnet.id

    dynamic "log" {
        for_each = setintersection(local.parsed_diag.log, local.diag_nsg_logs)
        content {
            category = log.value

            retention_policy {
                enabled = false
            }
        }
    }
}

resource "azurerm_subnet_network_security_group_association" "vnet" {
    network_security_group_id = azurerm_network_security_group.vnet.id
    subnet_id = azurerm_subnet.vnet.id
}

#
# Private DNS link
#

resource "azurerm_private_dns_zone_virtual_network_link" "main" {
    name = "${local.name_prefix_tf}-dnsl"
    private_dns_zone_name = local.hub_dns_zone_name
    provider = azurerm.production
    registration_enabled = true
    resource_group_name = local.hub_resource_group
    virtual_network_id = azurerm_virtual_network.vnet.id

    tags = merge( local.common_tags, local.extra_tags, var.tags )
}

#
# Peering
#

resource "azurerm_virtual_network_peering" "spoke-to-hub" {
    name = "${local.name_prefix_tf}-vnp-to-hub"
    resource_group_name = azurerm_resource_group.rg.name
    virtual_network_name = azurerm_virtual_network.vnet.name
    remote_virtual_network_id = data.azurerm_virtual_network.hub.id
    allow_virtual_network_access = true
    allow_forwarded_traffic = true
    allow_gateway_transit = true
    use_remote_gateways = true

    depends_on = [azurerm_virtual_network.vnet]
}

resource "azurerm_virtual_network_peering" "hub-to-spoke" {
    provider = azurerm.production
    name = "${local.name_prefix_tf}-vnp-from-hub"
    resource_group_name = local.hub_resource_group
    virtual_network_name = local.hub_virtual_network
    remote_virtual_network_id = azurerm_virtual_network.vnet.id
    allow_virtual_network_access = true
    allow_forwarded_traffic = true
    allow_gateway_transit = true
    use_remote_gateways = false

    depends_on = [azurerm_virtual_network_peering.spoke-to-hub]
}

#
# Permissions for Consul server discovery via Azure
# see: https://www.consul.io/docs/agent/cloud-auto-join
#

resource "azuread_group" "consul_server_discovery" {
    description = "The collection of users who are allowed to discover Consul server nodes on the network."
    name = "${local.name_prefix_tf}-adg-consul-cloud-join"
    prevent_duplicate_names = true
}
