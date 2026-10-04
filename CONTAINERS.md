# Containerized security tools

The root `compose.yaml` keeps each tool stack on its own Docker network. Scanner
inputs are mounted read-only, persistent state uses named volumes, and published
web/API ports bind to `127.0.0.1`. No service receives the Docker socket.

## Prepare

1. Copy `.env.example` to `.env` and replace every `replace-with-...` value with
   a unique, high-entropy secret. Hex-encoded random values avoid quoting issues
   in bootstrap JSON (for example, generate 32 random bytes with `openssl rand -hex 32`).
   Keep `.env` private; it is ignored by Git.
2. Use current Docker Desktop/Compose and keep its engine patched. For
   Elasticsearch, set the Docker Desktop VM `vm.max_map_count` to at least
   `262144` and allocate sufficient memory (the default JVM heaps alone reserve
   about 1.5 GiB for Elasticsearch and Logstash).
3. Review the image versions in `.env`. Mutable `latest` tags are used for Syft,
   Grype, Dependency-Track, and Elastic; replace these with verified release tags
   or image digests for repeatable deployments.

## Start profiles

Each profile is optional and can run independently:

```powershell
docker compose --profile dependency-track up -d --build
docker compose --profile elk up -d --build
docker compose --profile wazuh up -d --build
```

Dependency-Track opens its frontend at `http://127.0.0.1:8080` and API at
`http://127.0.0.1:8081`. Elasticsearch and the Dependency-Track database have
no published ports. Kibana is at `http://127.0.0.1:5601`; Logstash accepts
JSON-lines TCP input at `127.0.0.1:5044`. Its Elasticsearch writer is restricted
to the `soc-events-*` index family. Change Dependency-Track's initial admin
password immediately after first login. Wazuh manager agent and API ports are bound
to loopback on `1514`, `1515`, and `55000` by default. To enroll remote agents,
deliberately change the agent-port bindings and firewall rules for the trusted
agent network; do not expose the API publicly.

The Wazuh profile runs the manager only. It supports agent registration, API
access, and loopback syslog evidence ingestion. It does not deploy the Wazuh
indexer or dashboard; the separate ELK profile provides search and visualization.
Wazuh's full central stack also requires its indexer, dashboard, certificate
generation, and significantly more host resources, so the manager is kept
isolated here rather than represented as a complete stack.

## Generate assurance artifacts

Run the PowerShell wrappers from any working directory:

```powershell
.\security-assurance\syft\run.ps1
.\security-assurance\grype\run.ps1
```

Syft creates `data/sbom/sat_sa_sbom.json` as CycloneDX JSON. Grype consumes that
SBOM and writes `data/vulnerabilities/grype_report.json`; its vulnerability DB
is cached in a named volume. The scanner inputs are read-only, and only Grype
has outbound network access for vulnerability database updates. Syft itself is
offline. Upload the CycloneDX file to Dependency-Track through its UI/API when
that profile is running.

Stop an individual profile with the same profile flag and `down`. Named database,
index, and scanner-cache volumes persist until explicitly removed. Avoid
`docker compose down -v` unless deleting this evidence and service state is
intended.

These settings reduce exposure but are not a complete production security
boundary. Host firewalling, secret rotation, backups, vulnerability updates,
resource monitoring, and validating official image releases remain necessary.