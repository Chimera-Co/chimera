# Contributing to CHIMERA

Thanks for helping. CHIMERA runs live malware, so a few rules matter more here than in most projects; read
[Safety](#safety) before anything else. For the state of the project and the conventions in detail, read
[HANDOFF.md](HANDOFF.md).

## Get the code

```bash
git clone --recursive https://github.com/Chimera-Co/chimera.git
cd chimera
```

`--recursive` matters: DRAKVUF, PERDEDOR, the capa rules and the ReversingLabs YARA rules are submodules
(`git submodule update --init --recursive` fixes a plain clone).

## What you need

- **Code, tests, docs, console:** any Linux machine with Python 3.11, Node 22 and npm. No Xen needed.
- **Running analyses:** a bare-metal Intel host with VT-x and EPT, Debian 12 and Xen 4.19. DRAKVUF does not work
  under nested virtualisation or in cloud VMs. Check the CPU on the host itself:

  ```bash
  lscpu | grep -i flags | grep -w ept     # must print a line
  ```

  Then follow the [build guide](https://chimera-co.github.io/chimera/#/docs/build-host-xen).

## Run the tests

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/python -m pytest --confcutdir=test/unit test/unit       # backend
cd drakrun/web/frontend && npm ci && npx vitest run && npx eslint src
```

The static analyzer and the classifier have their own suites: `static_analyzer/tests` (run inside the static
image, see `static_analyzer/Containerfile`) and `classifier/tests` (see [classifier/RETRAIN.md](classifier/RETRAIN.md)). Changes to containment, the guest lifecycle or DRAKVUF integration also need a check on a real host
(see [verification](https://chimera-co.github.io/chimera/#/docs/verification)); say in the pull request what you ran.

## Making a change

1. Branch from `master` (`feature/…`, `fix/…`, `docs/…`).
2. Keep changes small and focused; match the style of the code around them (`black`/`isort` for Python, Prettier
   and ESLint for the console).
3. Add or update tests for behaviour you change.
4. Update the docs in the same pull request: user-facing pages are Markdown in
   `drakrun/web/frontend/src/docs/content/` (they appear in the console and on the documentation site); engineering
   notes and evidence go in `docs/chimera/`.
5. Open a pull request describing what changed, why, and how it was verified.

## Documentation site

The [documentation site](https://chimera-co.github.io/chimera/) is built from the console's own Home and Docs pages:

```bash
cd drakrun/web/frontend
npm run build:site            # output in dist-site/
```

`.github/workflows/pages.yml` publishes it on every push to `master` that touches the frontend.

## Safety

- Never commit samples, sample registers, API keys, archive passwords or analysis output from real malware.
- Never upload samples to third-party services; threat-intel lookups are hash-only by design.
- Do not weaken the containment checks (`chimera-net-check`, the fail-closed firewall) to make something work.
- Report security problems privately to the maintainer instead of opening a public issue.

## Licence

By contributing you agree that your contribution is licensed under the terms in [LICENSE](LICENSE), the DRAKVUF
Sandbox licence inherited from CERT Polska. Keep upstream licences and attribution intact.
