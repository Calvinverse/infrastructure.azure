#
# ENVIRONMENT
#

variable "category" {
    default = "nwk-spoke-xx"
    description = "The name of the category that all the resources are running in."
}

variable "environment" {
    default = "production"
    description = "The name of the environment that all the resources are running in."
}

#
# LOCATION
#

variable "location" {
    default = "australiaeast"
    description = "The full name of the Azure region in which the resources should be created."
}

#
# META
#

variable "meta_source" {
    description = "The commit ID of the current commit from which the plan is being created."
    type = string
}

variable "meta_version" {
    description = "The version of the infrastructure as it is being generated."
    type = string
}

#
# NETWORK
#

variable "address_space" {
    default = "10.1.10.0/24"
    description = "The full address space that is used the virtual network. Requires at least a /24 address space."
}

#
# NETWORK - DNS
#

variable "private_dns_zone" {
  description = "Name of private dns zone to create and associate with virtual network."
  default = "hub.azure.calvinverse.net"
}

#
# NETWORK - SECURITY RULES
#

variable "dmz_nsg_rules" {
  description = "Network security rules to add to dmz subnet. See README for details on how to setup."
  type = list(any)
  default = []
}

variable "management_nsg_rules" {
  description = "Network security rules to add to management subnet. See README for details on how to setup."
  type = list(any)
  default = []
}

#
# PEERING
#

variable "peering_assignment" {
  description = "List of principal ids that should have access to peer to this Hub network. All service principals used to deploy spoke networks should have access to peer."
  type = list(string)
  default = []
}

#
# SUBSCRIPTIONS
#

variable "subscription_production" {
    description = "The subscription ID of the production subscription. Used to find the log analytics resources."
    type = string
}

variable "subscription_test" {
    description = "The subscription ID of the test subscription."
    type = string
}

#
# TAGS
#

variable "tags" {
  description = "Tags to apply to all resources created."
  type = map(string)
  default = { }
}
