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

<<<<<<< HEAD
=======
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

>>>>>>> 46f80f8 (Use integration/.env ELASTICSEARCH_VERSION as stack version for cloude2e (#5252))
locals {
  // strip hash found in ELASTICSEARCH_VERSION in integration/.env to get stack_version
  dra_match       = regex("ELASTICSEARCH_VERSION=([0-9]+\\.[0-9]+\\.[0-9]+)(?:-[[:alpha:]]+-)?-?(SNAPSHOT)?", file("${path.module}/../../integration/.env"))
  stack_version   = local.dra_match[1] == "SNAPSHOT" ? format("%s-SNAPSHOT", local.dra_match[0]) : local.dra_match[0]
  docker_image_ea = var.elastic_agent_docker_image
}

<<<<<<< HEAD
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
  description="The Buildkite build id associated with this deployment"
}

variable "creator" {
  type=string
  default=""
  description="The Buildkite user who created the job"
}

resource "ec_deployment" "deployment" {
  name                   = format("fleet server PR %s", random_uuid.name.result)
  region                 = "gcp-us-west2"
  version                = local.stack_version
=======
data "ec_stack" "latest" {
  version_regex = local.stack_version
  region        = var.ess_region
}

resource "ec_deployment" "deployment" {
  name                   = format("fleet server PR-%s-%s", var.pull_request, var.git_commit)
  region                 = var.ess_region
  version                = data.ec_stack.latest.version
>>>>>>> 46f80f8 (Use integration/.env ELASTICSEARCH_VERSION as stack version for cloude2e (#5252))
  deployment_template_id = "gcp-general-purpose"

  tags = {
    "created_with_terraform" = "true"
    "docker_image_ea"        = local.docker_image_ea
    "provisioner" = "terraform"
    "pull_request" = var.pull_request
    "buildkite_id" = var.buildkite_id
    "creator" = var.creator
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
