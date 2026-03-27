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

:::{dropdown} Elastic Agent checkins to Fleet Server fail with "tried to parse field [local_metadata] as object, but found a concrete value" or "cannot unmarshal string into Go struct field Agent.components" errors.

**Applies to** {{fleet}} versions:
* 8.17.x (all patch versions)
* 8.18.x (all patch versions)
* 8.19.0 to 8.19.6
* 9.0.x (all patch versions)
* 9.1.0 to 9.1.6
* 9.2.0

On May 2, 2025 a series of known issues was uncovered that together cause checkins to Fleet Server to fail to parse the local_metadata field when
any of the audit_unenrolled_* unenrolled fields are present in an agent's entry in the .fleet-agents system index.

In {{fleet}} server's logs this will appear as:
```shell
elastic fail 400: document_parsing_exception: [1:209] object mapping for [local_metadata] tried to parse field [local_metadata] as object, but found a concrete value
Eat bulk checkin error; Keep on truckin'
```

And in the {{agent}} logs it will appear as:
```shell
"log.level":"error","@timestamp":"2025-04-22:12:35:25.295Z","message":"Eat bulk checkin error; Keep on truckin'","component":{"binary":"fleet-server","dataset":"elastic_agent.fleet_server","id":"fleet-server-es-containerhost","type":"fleet-server"},"log":{"source":"fleet-server-es-containerhost"},"service.type":"fleet-server","error.message":"elastic fail 400: document_parsing_exception: [1:209] object mapping for [local_metadata] tried to parse field [local_metadata] as object, but found a concrete value","ecs.version":"1.6.0","service.name":"fleet-server","ecs.version":"1.6.0"
```

A less common form of this bug can cause an `cannot unmarshal string into Go struct field Agent.components of type []model.ComponentsItem` error during checkin instead:
```shell
findAgentByApiKeyId: could not unmarshal ES document into model.Agent: json: cannot unmarshal string into Go struct field Agent.components of type []model.ComponentsItem
```

For more information, check [Issue #5674](https://github.com/elastic/fleet-server/issues/5674) and [Issue #5857](https://github.com/elastic/fleet-server/issues/5857).

All involved bugs were fixed in versions 8.19.7, 9.1.7, and 9.2.1.

**Workaround**

Upgrade to versions 8.19.7, 9.1.7, and 9.2.1 or above. Temporary work arounds are available that use queries to delete the relevant fields from the .fleet-agents index, however the problem can reoccur until the system is upgraded to a fixed version.

Refer to Elastic support knowledge base articles https://support.elastic.co/knowledge/19f2d377 and https://support.elastic.co/knowledge/77a3e589 for details of the work arounds.

:::
