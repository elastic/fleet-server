terraform {
  required_version = ">= 0.12.29"

  required_providers {
    ec = {
      source  = "elastic/ec"
      version = "0.12.2"
    }
  }
}

provider "ec" {}

variable "elastic_agent_docker_image" {
  type        = string
  description = "Elastic agent docker image with tag."
}

variable "git_commit" {
  type        = string
  default     = ""
  description = "The git commit ID."
}

variable "pull_request" {
  type        = string
  default     = ""
  description = "The github pull request number."
}

variable "ess_region" {
  type        = string
  default     = "gcp-us-west2"
  description = "The ESS region to use"
}

variable "deployment_template_id" {
  type        = string
  default     = "gcp-general-purpose"
  description = "The ess deployment template to use"
}

locals {
  // strip hash found in ELASTICSEARCH_VERSION in integration/.env to get stack_version
  dra_match       = regex("ELASTICSEARCH_VERSION=([0-9]+\\.[0-9]+\\.[0-9]+)(?:-[[:alpha:]]+-)?-?(SNAPSHOT)?", file("${path.module}/../../integration/.env"))
  stack_version   = local.dra_match[1] == "SNAPSHOT" ? format("%s-SNAPSHOT", local.dra_match[0]) : local.dra_match[0]
  docker_image_ea = var.elastic_agent_docker_image
}

data "ec_stack" "latest" {
  version_regex = local.stack_version
  region        = var.ess_region
}

resource "ec_deployment" "deployment" {
  name                   = format("fleet server PR-%s-%s", var.pull_request, var.git_commit)
  region                 = var.ess_region
  deployment_template_id = var.deployment_template_id
  version                = data.ec_stack.latest.version


  tags = {
    "source_repo"     = "elastic/fleet-server"
    "provisioner"     = "terraform"
    "docker_image_ea" = local.docker_image_ea
    "git_commit"      = var.git_commit
    "pull_request"    = var.pull_request
  }

  elasticsearch = {
    hot = {
      autoscaling = {}
      size        = "8g"
      zone_count  = 2
    }
  }

  kibana = {
    size       = "1g"
    zone_count = 1
  }

  integrations_server = {
    size       = "1g"
    zone_count = 1
    config = {
      docker_image = local.docker_image_ea
    }
  }
}
