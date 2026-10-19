# Testing and Evidence

Public pull-request CI must run Python and bundle smoke tests using disposable environments, including both Debian 13 and AlmaLinux 10. Tests are not equivalent to a security audit or live host compatibility certification.

Run the relevant unit, CLI, install, upgrade, signature, failover, concurrency, crash/recovery and offline-dependency tests on the exact reviewed source revision. Inspect job steps and logs, not merely workflow labels. The historic v0.3.0 private-release migration is intentionally disabled in public automated workflows pending a safe fixture strategy.

An actual signed release, ruleset enforcement and a positive production readiness decision require separate owner approval and evidence. Never assert real systemd or SELinux host tests were executed when they were deferred.
