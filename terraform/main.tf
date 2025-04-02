# --- Provider Configuration & Backend ---

terraform {
  required_version = ">= 1.0" # Specify minimum Terraform version

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0" # Pin Azure provider version for consistency
    }
  }

  # --- Backend Configuration (Recommended for Collaboration) ---
  # For enterprise use, configure a remote backend like Azure Blob Storage
  # to securely store and share Terraform state.
  # backend "azurerm" {
  #   resource_group_name  = "tfstate-rg"             # Name of RG for Terraform state
  #   storage_account_name = "tfstatesa<unique_suffix>" # Name of Storage Account for Terraform state
  #   container_name       = "tfstate"                # Name of Blob Container for Terraform state
  #   key                  = "project_group_x/prod.terraform.tfstate" # State file path (use variables for project/env)
  # }
}

provider "azurerm" {
  features {}
  # Consider configuring subscription_id, tenant_id etc. via environment variables or other secure methods
  # rather than hardcoding them in the provider block.
}

# --- Input Variables ---
# Define variables to make the template reusable for different projects/environments

variable "project_name" {
  description = "A short name for the project or logical group (e.g., 'billing', 'auth'). Used in naming resources."
  type        = string
  default     = "gitops" # Default value, override as needed
}

variable "environment" {
  description = "The deployment environment (e.g., 'dev', 'stg', 'prod')."
  type        = string
  default     = "prod" # Default value, override as needed
}

variable "location" {
  description = "The Azure region where resources will be deployed."
  type        = string
  default     = "East US"
}

variable "location_short" {
  description = "A short code for the Azure region (e.g., 'eus', 'weu'). Used in naming."
  type        = string
  default     = "eus" # Default value corresponding to 'East US'
}

variable "vnet_address_space" {
  description = "The main address space for the Virtual Network."
  type        = list(string)
  default     = ["10.0.0.0/16"]
}

variable "aks_subnet_address_prefix" {
  description = "The address prefix for the AKS subnet."
  type        = list(string)
  default     = ["10.0.1.0/24"]
}

variable "app_gateway_subnet_address_prefix" {
  description = "The address prefix for the Application Gateway subnet. Must be /24 or larger."
  type        = list(string)
  default     = ["10.0.2.0/24"]
}

variable "aks_node_count" {
  description = "The default number of nodes in the AKS node pool."
  type        = number
  default     = 3
}

variable "aks_min_node_count" {
  description = "The minimum number of nodes for AKS autoscaling."
  type        = number
  default     = 3
}

variable "aks_max_node_count" {
  description = "The maximum number of nodes for AKS autoscaling."
  type        = number
  default     = 10
}

variable "aks_vm_size" {
  description = "The VM size for the AKS nodes."
  type        = string
  default     = "Standard_D4s_v3"
}

variable "aks_enable_azure_ad" {
  description = "Enable Azure AD integration for AKS RBAC."
  type        = bool
  default     = false # Set to true and provide group IDs for production
}

variable "aks_azure_ad_admin_group_ids" {
  description = "List of Azure AD group object IDs to grant AKS cluster admin role."
  type        = list(string)
  default     = [] # Replace with actual AAD Group Object IDs if aks_enable_azure_ad is true
}

variable "flux_git_repo_url" {
  description = "The URL of the Git repository for Flux configuration."
  type        = string
  # default = "https://github.com/your-org/your-repo.git" # Provide a default or pass via tfvars/CI/CD
  sensitive   = true # Mark as sensitive if it's a private repo URL
}

variable "flux_git_branch" {
  description = "The branch of the Git repository for Flux to track."
  type        = string
  default     = "main"
}

variable "flux_sync_path" {
  description = "The path within the Git repository containing Kubernetes manifests for Flux."
  type        = string
  default     = "./manifests"
}

variable "dns_zone_name" {
  description = "The name of the DNS zone to create or use (e.g., 'contoso.com')."
  type        = string
  # default = "yourdomain.com" # Provide a default or pass via tfvars/CI/CD
}

variable "tags" {
  description = "A map of tags to apply to all resources."
  type        = map(string)
  default = {
    "Project"     = "gitops" # Default, will be overridden by local.tags
    "Environment" = "prod"   # Default, will be overridden by local.tags
    "ManagedBy"   = "Terraform"
  }
}

# --- Locals ---
# Use locals for constructing names and defining consistent values

locals {
  # Base name prefix using project and environment
  base_name = "${var.project_name}-${var.environment}"
  # Resource name prefix including location short code
  resource_prefix = "${local.base_name}-${var.location_short}"

  # Consistent tags applied to all resources
  tags = merge(var.tags, {
    Project     = var.project_name
    Environment = var.environment
  })

  # Name for the DNS CNAME record, often related to the ingress or specific service
  # This might be better managed by ExternalDNS within Kubernetes.
  # Example: Using 'apps' as a subdomain for applications served via ingress.
  dns_cname_record_name = "apps"
}

# --- Resource Group ---

resource "azurerm_resource_group" "main_rg" {
  name     = "${local.resource_prefix}-rg"
  location = var.location
  tags     = local.tags
}

# --- Networking ---

resource "azurerm_virtual_network" "vnet" {
  name                = "${local.resource_prefix}-vnet"
  location            = azurerm_resource_group.main_rg.location
  resource_group_name = azurerm_resource_group.main_rg.name
  address_space       = var.vnet_address_space
  tags                = local.tags
}

resource "azurerm_subnet" "aks_subnet" {
  name                 = "aks-snet" # Standardized subnet name part
  resource_group_name  = azurerm_resource_group.main_rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = var.aks_subnet_address_prefix
}

resource "azurerm_subnet" "app_gateway_subnet" {
  name                 = "appgw-snet" # Standardized subnet name part
  resource_group_name  = azurerm_resource_group.main_rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = var.app_gateway_subnet_address_prefix
}

resource "azurerm_network_security_group" "aks_nsg" {
  name                = "${local.resource_prefix}-aks-nsg"
  location            = azurerm_resource_group.main_rg.location
  resource_group_name = azurerm_resource_group.main_rg.name
  tags                = local.tags

  # Add necessary security rules here. Example: Allow Kubelet communication
  # security_rule {
  #   name                       = "AllowKubeletInbound"
  #   priority                   = 100
  #   direction                  = "Inbound"
  #   access                     = "Allow"
  #   protocol                   = "Tcp"
  #   source_port_range          = "*"
  #   destination_port_range     = "10250"
  #   source_address_prefix      = "VirtualNetwork" # Adjust as needed
  #   destination_address_prefix = "*"
  # }
  # Add rules for Load Balancer probes, VNet traffic, etc.
}

resource "azurerm_subnet_network_security_group_association" "aks_nsg_assoc" {
  subnet_id                 = azurerm_subnet.aks_subnet.id
  network_security_group_id = azurerm_network_security_group.aks_nsg.id
}

# --- Public IP for Application Gateway ---
resource "azurerm_public_ip" "app_gateway_pip" {
  name                = "${local.resource_prefix}-appgw-pip"
  resource_group_name = azurerm_resource_group.main_rg.name
  location            = azurerm_resource_group.main_rg.location
  allocation_method   = "Static"
  sku                 = "Standard" # Standard SKU required for AGIC and AZ support
  zones               = ["1", "2", "3"] # Deploy across Availability Zones for resilience
  tags                = local.tags
}

# --- Application Gateway for AGIC ---
resource "azurerm_application_gateway" "app_gateway" {
  name                = "${local.resource_prefix}-appgw"
  resource_group_name = azurerm_resource_group.main_rg.name
  location            = azurerm_resource_group.main_rg.location
  tags                = local.tags

  sku {
    name     = "Standard_v2" # v2 SKU required for AGIC
    tier     = "Standard_v2"
    capacity = 2 # Start with 2, adjust based on load
  }

  gateway_ip_configuration {
    name      = "appGatewayIpConfig"
    subnet_id = azurerm_subnet.app_gateway_subnet.id
  }

  frontend_port {
    name = "httpPort"
    port = 80
  }
  frontend_port {
    name = "httpsPort"
    port = 443
  }

  frontend_ip_configuration {
    name                 = "appGatewayFrontendIp"
    public_ip_address_id = azurerm_public_ip.app_gateway_pip.id
  }

  backend_address_pool {
    name = "defaultBackendPool" # AGIC will manage pools, but one is needed initially
  }

  backend_http_settings {
    name                  = "defaultHttpSettings" # AGIC will manage settings
    cookie_based_affinity = "Disabled"
    port                  = 80
    protocol              = "Http"
    request_timeout       = 20
  }

  http_listener {
    name                           = "defaultListener" # AGIC will manage listeners
    frontend_ip_configuration_name = "appGatewayFrontendIp"
    frontend_port_name             = "httpPort" # Start with HTTP, AGIC adds HTTPS
    protocol                       = "Http"
  }

  request_routing_rule {
    name                       = "defaultRule" # AGIC will manage rules
    rule_type                  = "Basic"
    http_listener_name         = "defaultListener"
    backend_address_pool_name  = "defaultBackendPool"
    backend_http_settings_name = "defaultHttpSettings"
    priority                   = 20000 # Low priority, AGIC rules take precedence
  }

  zones = ["1", "2", "3"] # Deploy across Availability Zones

  # Enable WAF (Optional but Recommended)
  # waf_configuration {
  #   enabled                  = true
  #   firewall_mode            = "Prevention" # Or "Detection"
  #   rule_set_type            = "OWASP"
  #   rule_set_version         = "3.1" # Or latest supported version
  # }
}

# --- DNS Configuration (Optional - Consider ExternalDNS in K8s) ---
# Creates a DNS Zone (if you manage DNS in Azure)
resource "azurerm_dns_zone" "main_dns_zone" {
  count               = var.dns_zone_name != "" ? 1 : 0 # Only create if dns_zone_name is provided
  name                = var.dns_zone_name
  resource_group_name = azurerm_resource_group.main_rg.name # Can be in a separate RG
  tags                = local.tags
}

# Creates a CNAME record pointing to the Application Gateway's public IP FQDN
# This is a simple approach. ExternalDNS in Kubernetes offers more dynamic updates.
resource "azurerm_dns_cname_record" "app_gateway_cname" {
  count = var.dns_zone_name != "" ? 1 : 0 # Only create if dns_zone_name is provided

  name                = local.dns_cname_record_name # e.g., "apps"
  zone_name           = azurerm_dns_zone.main_dns_zone[0].name
  resource_group_name = azurerm_resource_group.main_rg.name # Should match DNS Zone's RG
  ttl                 = 300
  record              = azurerm_public_ip.app_gateway_pip.fqdn # Point to App Gateway FQDN

  tags = local.tags
}


# --- Azure Kubernetes Service (AKS) ---

resource "azurerm_kubernetes_cluster" "aks" {
  name                = "${local.resource_prefix}-aks"
  location            = azurerm_resource_group.main_rg.location
  resource_group_name = azurerm_resource_group.main_rg.name
  dns_prefix          = "${local.base_name}-aks" # Unique DNS prefix for the AKS cluster API server
  tags                = local.tags

  default_node_pool {
    name                  = "default"
    node_count            = var.aks_node_count
    vm_size               = var.aks_vm_size
    vnet_subnet_id        = azurerm_subnet.aks_subnet.id
    enable_auto_scaling   = true
    min_count             = var.aks_min_node_count
    max_count             = var.aks_max_node_count
    os_disk_size_gb       = 128 # Example: Explicitly set OS disk size
    type                  = "VirtualMachineScaleSets"
    zones                 = ["1", "2", "3"] # Distribute nodes across Availability Zones
    enable_node_public_ip = false # Recommended for security
    tags                  = local.tags
    # Consider adding taints for system node pools if you add user node pools
  }

  # System-Assigned Managed Identity for AKS cluster operations
  identity {
    type = "SystemAssigned"
  }

  # Enable Azure AD integration for RBAC (Recommended)
  azure_ad_profile {
    managed             = true
    admin_group_object_ids = var.aks_enable_azure_ad ? var.aks_azure_ad_admin_group_ids : []
    azure_rbac_enabled  = true # Use Azure RBAC for Kubernetes authorization
  }

  network_profile {
    network_plugin    = "azure" # Use Azure CNI
    network_policy    = "azure" # Enable Azure Network Policy (requires Azure CNI)
    load_balancer_sku = "standard" # Required for Availability Zones
    outbound_type     = "loadBalancer" # Default, consider UDR for controlled egress
  }

  # Enable Application Gateway Ingress Controller (AGIC) Add-on
  ingress_application_gateway {
    gateway_id = azurerm_application_gateway.app_gateway.id
  }

  # Enable Azure Policy Add-on (Optional but Recommended)
  # azure_policy_enabled = true

  # Enable Secret Store CSI Driver for Key Vault integration (Recommended)
  # key_vault_secrets_provider {
  #   secret_rotation_enabled = true
  # }

  # Enable Monitoring Add-on (Connects to Log Analytics)
  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.log_analytics.id
  }

  # Define dependency on AGIC setup
  depends_on = [
    azurerm_application_gateway.app_gateway,
    azurerm_role_assignment.aks_agic_identity_roles # Ensure roles are assigned before cluster depends on AGIC
  ]
}

# --- Monitoring & Logging ---

resource "azurerm_log_analytics_workspace" "log_analytics" {
  name                = "${local.resource_prefix}-log"
  resource_group_name = azurerm_resource_group.main_rg.name
  location            = azurerm_resource_group.main_rg.location
  sku                 = "PerGB2018" # Standard Log Analytics SKU
  retention_in_days   = 30        # Adjust retention as needed
  tags                = local.tags
}

resource "azurerm_application_insights" "app_insights" {
  name                = "${local.resource_prefix}-appinsights"
  resource_group_name = azurerm_resource_group.main_rg.name
  location            = azurerm_resource_group.main_rg.location
  application_type    = "web"
  workspace_id        = azurerm_log_analytics_workspace.log_analytics.id # Link to Log Analytics workspace
  tags                = local.tags
}

# --- Container Registry (ACR) ---

resource "azurerm_container_registry" "acr" {
  name                = replace("${var.project_name}${var.environment}acr", "-", "") # ACR names must be alphanumeric and globally unique
  resource_group_name = azurerm_resource_group.main_rg.name
  location            = azurerm_resource_group.main_rg.location
  sku                 = "Premium" # Premium allows VNet integration, geo-replication etc. Consider Standard if not needed.
  admin_enabled       = false     # Good practice: Use token/service principal auth instead of admin user
  # georeplications     = [] # Configure geo-replication if needed for DR/proximity
  # network_rule_set { # Consider restricting access via VNet/Private Endpoint
  #   default_action = "Deny"
  #   ip_rule        = []
  #   virtual_network {
  #     action    = "Allow"
  #     subnet_id = azurerm_subnet.aks_subnet.id # Allow AKS subnet
  #   }
  # }
  tags = local.tags
}

# --- Role Assignments ---

# Grant AKS Kubelet Identity permission to pull images from ACR
resource "azurerm_role_assignment" "aks_kubelet_acr_pull" {
  scope                = azurerm_container_registry.acr.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_kubernetes_cluster.aks.kubelet_identity[0].object_id # Use Kubelet identity for pulling images
}

# Grant AKS Cluster Identity permissions needed for AGIC
# The AGIC add-on creates a user-assigned identity in the node resource group.
# This identity needs permissions on the Application Gateway.
# Note: Terraform might not automatically know the principal ID of the AGIC identity created by Azure.
# Manual assignment or using data sources after initial apply might be needed if this fails.
# However, enabling the add-on *should* configure necessary permissions automatically.
# If issues arise, grant 'Contributor' role on the App Gateway to the AKS Cluster's *Control Plane* Identity.
resource "azurerm_role_assignment" "aks_agic_identity_roles" {
  scope                = azurerm_application_gateway.app_gateway.id
  role_definition_name = "Contributor" # Required role for AGIC identity on the App Gateway
  principal_id         = azurerm_kubernetes_cluster.aks.identity[0].principal_id # AKS Cluster (Control Plane) Identity
}

# Grant AKS Cluster Identity permissions to join the App Gateway's subnet
resource "azurerm_role_assignment" "aks_appgw_subnet_join" {
  scope                = azurerm_subnet.app_gateway_subnet.id
  role_definition_name = "Network Contributor" # Allows joining the subnet
  principal_id         = azurerm_kubernetes_cluster.aks.identity[0].principal_id # AKS Cluster (Control Plane) Identity
}


# --- GitOps Configuration (Flux) ---

resource "azurerm_kubernetes_flux_configuration" "flux" {
  name       = "flux-config" # Standardized name for the Flux config resource
  cluster_id = azurerm_kubernetes_cluster.aks.id
  namespace  = "flux-system" # Deploy Flux components into their own namespace

  git_repository {
    url              = var.flux_git_repo_url
    reference_type   = "branch" # Or 'tag', 'commit'
    reference_value  = var.flux_git_branch
    sync_interval_in_seconds = 600 # Sync every 10 minutes (adjust as needed)
    # https_ca_cert    = "" # Provide if using self-signed certs
    # https_key        = "" # Provide private key if needed for HTTPS auth (use sensitive var)
    # ssh_private_key  = "" # Provide private key if needed for SSH auth (use sensitive var)
  }

  kustomizations = {
    app = { # Name of the first kustomization (can have multiple)
      path = var.flux_sync_path
      # depends_on = [] # Define dependencies between kustomizations if needed
      sync_interval_in_seconds = 600
      prune = true # Automatically delete resources removed from Git
    }
  }

  scope = "cluster" # Apply Flux config at the cluster level

  depends_on = [
    # Ensure ACR pull secret is potentially configured by Flux/workloads before applying Flux itself,
    # although the role assignment should cover node image pulls.
    azurerm_role_assignment.aks_kubelet_acr_pull,
  ]
}


# --- Outputs ---
# Output useful information after deployment

output "resource_group_name" {
  description = "The name of the main resource group."
  value       = azurerm_resource_group.main_rg.name
}

output "aks_cluster_name" {
  description = "The name of the AKS cluster."
  value       = azurerm_kubernetes_cluster.aks.name
}

output "aks_cluster_id" {
  description = "The ID of the AKS cluster."
  value       = azurerm_kubernetes_cluster.aks.id
}

output "aks_kubeconfig_raw" {
  description = "Raw Kubeconfig for the AKS cluster (sensitive)."
  value       = azurerm_kubernetes_cluster.aks.kube_config_raw
  sensitive   = true
}

# To get Kubeconfig for Azure AD integrated cluster:
# az aks get-credentials --resource-group <resource_group_name> --name <aks_cluster_name> --admin (for admin access)
# az aks get-credentials --resource-group <resource_group_name> --name <aks_cluster_name> (for user access via AAD login)

output "acr_login_server" {
  description = "The login server hostname for the Azure Container Registry."
  value       = azurerm_container_registry.acr.login_server
}

output "acr_id" {
  description = "The ID of the Azure Container Registry."
  value       = azurerm_container_registry.acr.id
}

output "log_analytics_workspace_id" {
  description = "The ID of the Log Analytics workspace."
  value       = azurerm_log_analytics_workspace.log_analytics.id
}

output "log_analytics_workspace_customer_id" {
  description = "The Customer ID (Workspace ID) of the Log Analytics workspace."
  value       = azurerm_log_analytics_workspace.log_analytics.workspace_id
}

output "application_insights_instrumentation_key" {
  description = "The Instrumentation Key for Application Insights."
  value       = azurerm_application_insights.app_insights.instrumentation_key
  sensitive   = true
}

output "application_insights_connection_string" {
  description = "The Connection String for Application Insights."
  value       = azurerm_application_insights.app_insights.connection_string
  sensitive   = true
}

output "application_gateway_public_ip_address" {
  description = "The Public IP address of the Application Gateway."
  value       = azurerm_public_ip.app_gateway_pip.ip_address
}

output "application_gateway_public_ip_fqdn" {
  description = "The FQDN of the Application Gateway's Public IP."
  value       = azurerm_public_ip.app_gateway_pip.fqdn
}

output "dns_cname_record_fqdn" {
  description = "The FQDN of the created CNAME record pointing to the Application Gateway (if DNS zone was created)."
  value       = try(azurerm_dns_cname_record.app_gateway_cname[0].fqdn, "DNS Zone/Record not created")
}

