terraform {
  required_version = ">= 0.12.29"

  required_providers {
    ec = {
      source  = "elastic/ec"
      version = "0.5.1"
    }
  }
}

provider "ec" {}

variable "elastic_agent_docker_image" {
  type        = string
  description = "Elastic agent docker image with tag."
}

locals {
  match           = regex("const DefaultVersion = \"(.*)\"", file("${path.module}/../../../version/version.go"))[0]
  stack_version   = format("%s-SNAPSHOT", local.match)
  docker_image_ea = var.elastic_agent_docker_image
}

resource "random_uuid" "name" {
}

variable "pull_request" {
  type=string
  default=""
  description="The github pull request number"
}

variable "buildkite_id" {
  type=string
  default=""
  description="The buildkite build id associated with this deployment"
}

resource "ec_deployment" "deployment" {
  name                   = format("fleet server PR %s", random_uuid.name.result)
  region                 = "gcp-us-west2"
  version                = local.stack_version
  deployment_template_id = "gcp-io-optimized-v2"

  tags = {
    "created_with_terraform" = "true"
    "docker_image_ea"        = local.docker_image_ea
    "provisioner" = "terraform"
    "pull_request" = var.pull_request
    "buildkite_id" = var.buildkite_id
}

  elasticsearch {}

  kibana {}

  integrations_server {
    config {
      docker_image = local.docker_image_ea
    }
  }
}
