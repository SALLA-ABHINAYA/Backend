provider "azurerm" {
  features {}
}

# Create a Resource Group
resource "azurerm_resource_group" "backend_rg" {
  name     = "backend-resource-group"
  location = "East US"
}

# Create a Virtual Network
resource "azurerm_virtual_network" "backend_vnet" {
  name                = "backend-vnet"
  location            = azurerm_resource_group.backend_rg.location
  resource_group_name = azurerm_resource_group.backend_rg.name
  address_space       = ["10.0.0.0/16"]
}  

# Create a Subnet
resource "azurerm_subnet" "backend_subnet" {
  name                 = "backend-subnet"
  resource_group_name  = azurerm_resource_group.backend_rg.name
  virtual_network_name = azurerm_virtual_network.backend_vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

# Create an AKS Cluster with Auto-Scaling and GitOps Integration
resource "azurerm_kubernetes_cluster" "backend_aks" {
  name                = "backend-aks"
  location            = azurerm_resource_group.backend_rg.location
  resource_group_name = azurerm_resource_group.backend_rg.name
  dns_prefix          = "backend-cluster"

  default_node_pool {
    name                = "systempool"
    node_count          = 2
    vm_size             = "Standard_D2s_v3"
    vnet_subnet_id      = azurerm_subnet.backend_subnet.id
    enable_auto_scaling = true
    min_count           = 2
    max_count           = 4
  }

  identity {
    type = "SystemAssigned"
  }

  # Enable Azure AD integration
  azure_active_directory_role_based_access_control {
    managed = true
  }

  network_profile {
    network_plugin = "azure"
  }

  gitops {
    name          = "backend-gitops"
    namespace     = "backend"
    url           = "https://github.com/yourusername/backend-deployment.git"
    branch        = "main"
    path          = "k8s"
    sync_interval = "3m"
  }

  depends_on = [azurerm_subnet.backend_subnet]
}

# Create a Storage Account for Logs
resource "azurerm_storage_account" "backend_storage" {
  name                     = "backendstoragelog"
  resource_group_name      = azurerm_resource_group.backend_rg.name
  location                 = azurerm_resource_group.backend_rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

# Create a Storage Container
resource "azurerm_storage_container" "backend_logs" {
  name                  = "backend-logs"
  storage_account_name  = azurerm_storage_account.backend_storage.name
  container_access_type = "private"
}

# Create a Network Security Group (NSG)
resource "azurerm_network_security_group" "backend_nsg" {
  name                = "backend-nsg"
  location            = azurerm_resource_group.backend_rg.location
  resource_group_name = azurerm_resource_group.backend_rg.name
}

# Allow Inbound Traffic to AKS
resource "azurerm_network_security_rule" "allow_aks" {
  name                        = "AllowAKSInbound"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.backend_rg.name
  network_security_group_name = azurerm_network_security_group.backend_nsg.name
}

# Output the AKS Cluster Name and Storage Account
output "aks_cluster_name" {
  value = azurerm_kubernetes_cluster.backend_aks.name
}

output "storage_account_name" {
  value = azurerm_storage_account.backend_storage.name
}
