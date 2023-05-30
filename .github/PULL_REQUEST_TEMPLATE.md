<!-- Type of change
Please label this PR with one of the following labels, depending on the scope of your change:
- Bug
- Enhancement
- Breaking change
- Deprecation
- Cleanup
- Docs
-->

## What is the problem this PR solves?

// Please do not just reference an issue. Explain WHAT the problem this PR solves here.

## How does this PR solve the problem?

// Explain HOW you solved the problem in your code. It is possible that during PR reviews this changes and then this section should be updated.


## How to test this PR locally

<!-- Recommended
Explain here how this PR will be tested by the reviewer if anything special is needed for manual testing: commands, dependencies, steps, etc.
-->

## Design Checklist

<!-- Mandatory
This checklist is a reminder about high level design problems that should be considered for any change made to fleet server.
-->

- [ ] I have ensured my design is stateless and will work when multiple fleet-server instances are behind a load balancer.
- [ ] I have or intend to scale test my changes, ensuring it will work reliably with 100K+ agents connected.
- [ ] I have included fail safe mechanisms to limit the load on fleet-server: rate limiting, circuit breakers, caching, load shedding, etc.

## Checklist

<!-- Mandatory
This checklist is to help creators of PRs to find parts which might not be directly related to code change but still need to be addressed. Anything that does not apply to the PR should be removed from the checklist.
-->

- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] I have made corresponding change to the default configuration files
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] I have added an entry in `./changelog/fragments` using the [changelog tool](https://github.com/elastic/fleet-server#changelog)


## Related issues

<!-- Recommended
Link related issues below. Insert the issue link or reference after the word "Closes" if merging this should automatically close it.

- Closes #123
- Relates #123
- Requires #123
- Superseds #123
-->
