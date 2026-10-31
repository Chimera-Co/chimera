# Instructions for coding agents

Read [HANDOFF.md](HANDOFF.md) first: architecture, current state, deploy procedure, tests and the project's rules.

## Working rules

- Match the surrounding code: naming, comment density, idioms. Python is formatted with black/isort; the console with
  Prettier and ESLint. Add tests next to the existing ones (`test/unit/`, `classifier/tests/`,
  `static_analyzer/tests/`, `drakrun/web/frontend/src/**/*.test.jsx`).
- Run the relevant suites before you call a change done (HANDOFF.md §5) and report the exact result.
- Report what you verified and what you did not. Code that exists is not proof that a guest-side mechanism works;
  only a run on the host shows that.
- If `graphify-out/` exists, use `graphify query "<question>"` to orient yourself, and run `graphify update .` after
  changing code.

## Do not

- Deploy, restart services, run analyses, or change VMs, Xen, iptables or systemd unless the task says so and you
  have root on the sandbox host.
- Download, open or run malware samples; read or print keys, credentials or archive passwords.
- Commit samples, hash registers, analysis output from `/var/lib`, keys, personal data or `install.json`. The
  repository is public.
- Weaken containment (`chimera-net-check`, the firewall) to get something working.
- Add `Co-authored-by` trailers to commits.
