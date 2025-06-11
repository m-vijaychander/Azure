provider "azurerm" {
    features {}
}

terraform {
    required_providers {
        azurerm = {
        source  = "hashicorp/azurerm"
        version = "~> 3.0"
        }
    }    
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

resource "azurerm_kubernetes_cluster" "azdevops" {
    name                = "example-aks-cluster"
    location            = azurerm_resource_group.example.location
    resource_group_name = azurerm_resource_group.example.name
    dns_prefix          = "exampleaks"
    
    default_node_pool {
        name       = "azdevopspool"
        node_count = 3
        vm_size    = "Standard_DS2_v2"
    }
    
    identity {
        type = "SystemAssigned"
    }
    
    tags = {
        environment = "Terraform"
    }
}
