---
navigation_title: Known issues
products:
  - id: fleet
applies_to:
  stack: ga
sub:
  product: Fleet Server
---

# {{product}} known issues

Known issues are significant defects or limitations that may impact your implementation. These issues are actively being worked on and will be addressed in a future release. Review the {{product}} known issues to help you make informed decisions, such as upgrading to a new version.

% Use the following template to add entries to this page.

% :::{dropdown} Title of known issue
% **Applicable versions for the known issue and the version for when the known issue was fixed**
% On [Month Day, Year], a known issue was discovered that [description of known issue].
% For more information, check [Issue #](Issue link).

% **Workaround**
% Workaround description.
% :::


:::{dropdown} Manual DEB/RPM upgrades of {{fleet}}-managed agents fail when "Agent tamper protection" is enabled

**Applies to**: {{agent}} 8.19.2, 9.1.2

On August 19, 2025, a known issue was discovered where manual DEB/RPM upgrades of {{fleet}}-managed {{agents}} fail if the {{elastic-defend}} integration is installed and **Agent tamper protection** is enabled in the agent policy. When this occurs, the log contains an output similar to the following:

```
Invalid uninstall token: exit status 28
```

This issue only impacts manual DEB/RPM upgrades from {{agent}} 8.19.2 or 9.1.2. Managed upgrades performed through {{fleet}} are not affected.

For more information, refer to [PR #9462](https://github.com/elastic/elastic-agent/pull/9462).

**Workaround**

You can use one of the following workarounds to resolve the issue:

- Stop the `elastic-agent` service:

   Before installing the {{agent}} DEB/RPM package, run `systemctl stop elastic-agent`, then proceed with the installation. This solution works even when reinstalling the same version of {{agent}}.

- Temporarily remove the {{elastic-defend}} integration:

   Before upgrading, move the agent to an agent policy without the {{elastic-defend}} integration. Wait for the change to take effect, proceed with the upgrade, then move the agent to its previous policy.

- Disable **Agent tamper protection**:

   Before upgrading, disable **Agent tamper protection** in the agent policy. Wait for the change to take effect, proceed with the upgrade, then move the agent back to its previous policy.

**Fixed in**: {{agent}} 8.19.3, 9.1.3
:::

:::{dropdown} [Windows] {{agent}} is unable to re-enroll into {{fleet}}

**Applies to**: {{agent}} 9.0.0, 9.0.1, 9.0.2 (Windows only)

On April 9, 2025, a known issue was discovered where an {{agent}} installed on Windows and previously enrolled into {{fleet}} is unable to re-enroll. Attempting to enroll the {{agent}} fails with the following error:

```shell
Error: the command is executed as root but the program files are not owned by the root user.
```

For more information, check [Issue #7794](https://github.com/elastic/elastic-agent/issues/7794).

**Workaround**

Until a bug fix is available in a later release, you can resolve the issue temporarily using the following workaround:

1. Change the ownership of the {{agent}} directory:

  ```shell
  icacls "C:\Program Files\Elastic\Agent" /setowner "NT AUTHORITY\SYSTEM" /t /l
  ```

2. After the output confirms all files were successfully processed, run the `enroll` command again.

:::

:::{dropdown} .fleet-agents template is missing mappings

**Applies to** {{fleet}} versions:
* 8.17.x (all patch versions)
* 8.18.0 to 8.18.7
* 8.19.0 to 8.19.3
* 9.0.0 to 9.0.7
* 9.1.0 to 9.1.3

On May 2, 2025 a known issue was discovered that the `.fleet-agents` index template was missing a mapping for the `local_metadata.complete` attribute. This may cause agent checkins to be rejected and the agents to appear as offline.

In this {{fleet}}'s logs this will appear as:
```shell
elastic fail 400: document_parsing_exception: [1:209] object mapping for [local_metadata] tried to parse field [local_metadata] as object, but found a concrete value
Eat bulk checkin error; Keep on truckin'
```

And in the {{agent}} logs it will appear as:
```shell
"log.level":"error","@timestamp":"2025-04-22:12:35:25.295Z","message":"Eat bulk checkin error; Keep on truckin'","component":{"binary":"fleet-server","dataset":"elastic_agent.fleet_server","id":"fleet-server-es-containerhost","type":"fleet-server"},"log":{"source":"fleet-server-es-containerhost"},"service.type":"fleet-server","error.message":"elastic fail 400: document_parsing_exception: [1:209] object mapping for [local_metadata] tried to parse field [local_metadata] as object, but found a concrete value","ecs.version":"1.6.0","service.name":"fleet-server","ecs.version":"1.6.0"
```

This attribute was added to the template in versions: 8.17.11 8.18.3, 8.19.3, 9.0.3, 9.1.0.

Further investigation revealed that the `.fleet-agents` index template was not correctly applied due to an unchanged `_meta.managed_index_mappings_version` number.
This change also affects other attributes as well, such as `upgrade_attempts`, `namespaces`, `unprivileged`, and `unhealthy_reason`.
If there is an error related to any of these attributes, there will be a similar error message in the logs.

**Workaround**
Updating to a version with a fixed `_meta.managed_index_mappings_version` will correctly apply the new index template.
The fixed versions are 8.18.8, 8.19.4, 9.0.8, 9.1.4.

:::
