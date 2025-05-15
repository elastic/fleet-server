terraform {
  required_version = ">= 0.12.29"

  required_providers {
    ec = {
      source  = "elastic/ec"
      version = "0.12.1"
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
  description = "The git commit id"
}

locals {
  match           = regex("const DefaultVersion = \"(.*)\"", file("${path.module}/../../../version/version.go"))[0]
  stack_version   = format("%s-SNAPSHOT", local.match)
  docker_image_ea = var.elastic_agent_docker_image
}

resource "random_uuid" "name" {
}

resource "ec_deployment" "deployment" {
  name                   = format("fleet server PR %s", random_uuid.name.result)
  region                 = "gcp-us-west2"
  version                = local.stack_version
  deployment_template_id = "gcp-general-purpose"

  tags = {
    "created_with_terraform" = "true"
    "source_repo"            = "elastic/fleet-server"
    "provisioner"            = "terraform"
    "docker_image_ea"        = local.docker_image_ea
    "git_commit"             = var.git_commit
  }

  elasticsearch = {
    hot = {
      autoscaling = {}
    }
  }

  kibana = {}

  integrations_server = {
    config = {
      docker_image = local.docker_image_ea
    }
  }
}
