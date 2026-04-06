terraform {
  backend "azurerm" {
    resource_group_name  = "rg-terraform-state"
    storage_account_name = "stsentinelsiem9272"
    container_name       = "tfstate"
    key                  = "sentinel-siem.tfstate"
  }
}