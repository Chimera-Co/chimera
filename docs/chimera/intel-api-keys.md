# Threat-intel API keys

Online lookups send hashes, domains, IPs and URLs to the providers below, never the sample. A provider without
its key is skipped and the console shows **No API key**. Each key is one file on the host, readable by root only:

| Provider | Key file | Needed? | Free account | Looks up |
|---|---|---|---|---|
| VirusTotal | `/etc/chimera/keys/virustotal` | yes | <https://www.virustotal.com/gui/join-us> | hashes, domains, IPs, URLs |
| AlienVault OTX | `/etc/chimera/keys/otx` | yes | <https://otx.alienvault.com/> | hashes, domains, IPs, URLs |
| AbuseIPDB | `/etc/chimera/keys/abuseipdb` | yes | <https://www.abuseipdb.com/register> | IPs |
| Hybrid Analysis | `/etc/chimera/keys/hybridanalysis` | yes | <https://www.hybrid-analysis.com/signup> | hashes |
| GreyNoise | `/etc/chimera/keys/greynoise` | optional (community API works without) | <https://viz.greynoise.io/signup> | IPs |
| RIPEstat | – | no key | – | IP routing context (ASN, holder, prefix) |
| urlscan.io | `/etc/chimera/keys/urlscan` | optional | <https://urlscan.io/user/signup> | domains |
| MalwareBazaar, ThreatFox, URLhaus | `/etc/chimera/abusech-auth-key` | yes (one abuse.ch key) | <https://auth.abuse.ch/> | hashes, IOCs |
| CIRCL hashlookup | – | no key | – | hashes (known software) |

## Where to find the key after signing up

- **AlienVault OTX**: log in, open <https://otx.alienvault.com/api>; the key is shown as "OTX Key".
- **AbuseIPDB**: log in, open <https://www.abuseipdb.com/account/api>, "Create Key". The free plan allows
  1,000 checks a day; CHIMERA stops at 900.
- **Hybrid Analysis**: log in, open your profile, then the **API key** tab, and create a key.
- **GreyNoise** (optional): log in, open account settings, then **API Key**. Without a key the free community
  endpoint is used.

## Paste a key

Each command asks for the key without echoing it and without putting it in the shell history, writes it with
mode 0600 and owner root, and does not print it. Run the one for the provider you signed up for:

```bash
read -rsp 'AlienVault OTX key: ' k && echo && printf '%s' "$k" | sudo install -D -m 0600 -o root -g root /dev/stdin /etc/chimera/keys/otx; unset k
```

```bash
read -rsp 'AbuseIPDB key: ' k && echo && printf '%s' "$k" | sudo install -D -m 0600 -o root -g root /dev/stdin /etc/chimera/keys/abuseipdb; unset k
```

```bash
read -rsp 'Hybrid Analysis key: ' k && echo && printf '%s' "$k" | sudo install -D -m 0600 -o root -g root /dev/stdin /etc/chimera/keys/hybridanalysis; unset k
```

```bash
read -rsp 'GreyNoise key: ' k && echo && printf '%s' "$k" | sudo install -D -m 0600 -o root -g root /dev/stdin /etc/chimera/keys/greynoise; unset k
```

Keys are read at every lookup, so no restart is needed. Check that the console now counts the provider as ready
(the key itself is never returned):

```bash
curl -s localhost:5000/api/intel/providers | python3 -c "import json,sys; print([(p['id'], p['configured']) for p in json.load(sys.stdin)['providers']])"
```

Then open a finished analysis and press **Run online lookup**. To remove a key, delete its file.

## Why a ready provider says "Nothing to look up"

A provider is only asked about the kinds of indicator it takes (the last column above). GreyNoise and AbuseIPDB
take public IP addresses only. In the sandbox, DNS answers and every connection go to the simulated Internet
(INetSim), and private and guest addresses are never sent, so most runs have no public IP to ask about. A run has
one when the sample connects to a hard-coded address, when one is in its strings, or when a C2 address is decoded
from its configuration in memory (malduck, see [static-analysis.md](static-analysis.md)). The console's provider
table says which kinds each provider takes.
