# wala-runner

Thin CLI + HTTP daemon wrapper around [IBM WALA](https://github.com/wala/WALA) for Java call-graph
reachability analysis.  Invoked by `services/analysis/wala_analyzer.py` inside
vuln-intel, but also fully usable as a standalone tool.

Produces the same JSON output schema as `sootup-runner` so both can be used
interchangeably or in fallback chains.

---

## Build

Requires Java 11+ and Maven 3.6+.

```bash
cd tools/wala-runner
mvn clean package -DskipTests
# → target/wala-runner.jar  (fat JAR, all deps bundled)
```

---

## CLI usage

### Single target

```bash
java -jar target/wala-runner.jar \
  --jar /path/to/library.jar \
  --target "com.example.VulnerableClass.vulnerableMethod"
```

### Batch (one callgraph build, N target queries)

```bash
java -jar target/wala-runner.jar \
  --jar /path/to/library.jar \
  --targets-file targets.json
```

`targets.json` is a JSON array of FQDN strings:
```json
["com.example.Foo.bar", "com.example.Baz.qux"]
```

### With L2 classpath (transitive dependency JARs)

Providing the dependency JARs lets WALA resolve cross-module signatures that
would otherwise cause failures:

```bash
java -jar target/wala-runner.jar \
  --jar /path/to/library.jar \
  --classpath-file /path/to/deps.json \
  --targets-file targets.json
```

`deps.json` is a JSON array of absolute JAR paths:
```json
["/home/user/.m2/.../spring-core-5.3.10.jar"]
```

Or use a directory scan:
```bash
java -jar target/wala-runner.jar \
  --jar library.jar \
  --classpath-dir /path/to/dep-dir \
  --targets-file targets.json
```

### Multi-JAR single target

```bash
java -jar target/wala-runner.jar \
  --jars-file jars.json \
  --target "com.example.Foo.bar"
```

---

## SBOM mode

Provide a CycloneDX or SPDX SBOM and let wala-runner download the required
JARs automatically from Maven Central.

### SBOM as L2 classpath (explicit L1 JAR)

```bash
java -jar target/wala-runner.jar \
  --jar /path/to/app.jar \
  --sbom bom.json \
  --target "com.example.Vulnerable.method"
```

All components found in the SBOM are downloaded and added to the L2 classpath.

### SBOM as both L1 and L2 (no explicit JAR)

```bash
java -jar target/wala-runner.jar \
  --sbom bom.json \
  --sbom-primary "com.example:my-app" \
  --target "com.example.Vulnerable.method"
```

`--sbom-primary` identifies which SBOM component becomes the L1 JAR under
analysis (`group:artifact` format). All other components become L2 classpath.

### Override the download cache

```bash
java -jar target/wala-runner.jar \
  --sbom bom.json \
  --sbom-primary "com.example:my-app" \
  --sbom-cache /data/jar-cache \
  --target "com.example.Vulnerable.method"
```

Default cache: `~/.cache/vuln-intel/jars/`

### Supported SBOM formats

| Format | Detection |
|--------|-----------|
| CycloneDX JSON | `bomFormat` or `components` top-level key |
| CycloneDX XML  | `.xml` extension, parses `<purl>` elements |
| SPDX JSON      | `spdxVersion` or `packages` top-level key |

All formats use `pkg:maven/GROUP/ARTIFACT@VERSION` Package URLs to identify
Maven components.

---

## Daemon mode

The daemon keeps a persistent JVM and an LRU callgraph context cache (up to 20
entries) so repeated queries against the same JAR avoid rebuilding the callgraph.

### Start

```bash
java -Xmx3g -jar target/wala-runner.jar --serve 7071
```

### Health check

```bash
curl http://localhost:7071/health
# → {"status":"ok","contexts_cached":3}
```

### Analyse request

```bash
curl -s -X POST http://localhost:7071/analyse \
  -H "Content-Type: application/json" \
  -d '{
    "jar":       "/abs/path/to/library.jar",
    "classpath": ["/abs/path/dep1.jar"],
    "targets":   ["com.example.Foo.bar"],
    "max_depth": 10
  }' | jq '.'
```

### Analyse with SBOM (daemon)

```bash
# Pass SBOM file path
curl -s -X POST http://localhost:7071/analyse \
  -H "Content-Type: application/json" \
  -d '{
    "sbom_file":    "/abs/path/to/bom.json",
    "sbom_primary": "com.example:my-app",
    "targets":      ["com.example.Vulnerable.method"],
    "max_depth":    10
  }' | jq '.'

# Or pass purls inline
curl -s -X POST http://localhost:7071/analyse \
  -H "Content-Type: application/json" \
  -d '{
    "jar":        "/abs/path/to/app.jar",
    "sbom_purls": [
      "pkg:maven/org.springframework/spring-core@5.3.10",
      "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.14.0"
    ],
    "targets":    ["org.springframework.core.Vulnerable.method"],
    "max_depth":  10
  }' | jq '.'
```

### All daemon request fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `jar` | string | No* | Absolute path to L1 JAR. Required unless `sbom_primary` given. |
| `classpath` | string[] | No | Additional L2 JAR paths. |
| `targets` | string[] | Yes | FQDNs to check reachability for. |
| `max_depth` | int | No | BFS depth limit (default 15). |
| `algo` | string | No | `cha` (default) or `0cfa`. |
| `sbom_file` | string | No | Absolute path to SBOM file. |
| `sbom_purls` | string[] | No | Inline list of `pkg:maven/...` purls. |
| `sbom_primary` | string | No* | `group:artifact` to use as L1 when `jar` is absent. |
| `sbom_cache` | string | No | Override JAR download cache directory. |

---

## JSON output schema

```json
{
  "reachable":    true,
  "entry_method": "com.example.App.main",
  "analysis_source": "wala_cha",
  "confidence":   0.70,
  "error":        null,
  "call_path": [
    { "fqdn": "com.example.App.main",       "class": "com.example.App",       "method": "main" },
    { "fqdn": "com.example.Vulnerable.go",  "class": "com.example.Vulnerable", "method": "go"  }
  ],
  "sink_to_source_call_path": [...],
  "reachable_entry_methods":  [...],
  "reachable_sources":        []
}
```

Batch output wraps results per target:
```json
{ "batch": true, "results": { "com.example.Foo.bar": { ... } } }
```

---

## Call-path quality scoring

Every call path is scored in `[0.0, 1.0]` before serialisation. The
highest-scoring path across all entry points is selected.

| Score | Meaning |
|-------|---------|
| ≥ 0.50 | Clean — stays in application code |
| 0.20–0.49 | Mixed — some framework hops but app code present |
| < 0.20 | Suppressed — JDK/framework bounce noise |

**Penalties per hop:**

| Pattern | Penalty |
|---------|---------|
| JDK class (`java.*`, `sun.*`, …) | −0.05 |
| Reflection (`java.lang.reflect.*`, …) | −0.05 |
| Logging framework (`org.slf4j.*`, `ch.qos.logback.*`, …) | −0.05 |
| Synthetic/proxy (`lambda$`, `access$`, `$$EnhancerBy…`) | −0.08 |
| Noise method (`toString`, `readObject`, `invoke`, …) | −0.03 |
| All hops are JDK | −0.10 extra |

Bonuses: +0.10 for path length ≤ 2, +0.05 for path length ≤ 4.

A second scoring pass runs in Python via `services/analysis/callpath_scorer.py`
after results are delivered to the platform.

---

## CLI flags reference

| Flag | Default | Description |
|------|---------|-------------|
| `--jar <path>` | — | L1 JAR to analyse |
| `--jars-file <path>` | — | JSON array of JAR paths (multi-jar mode) |
| `--target <fqdn>` | — | Single target FQDN |
| `--targets-file <path>` | — | JSON array of target FQDNs (batch mode) |
| `--classpath-file <path>` | — | JSON array of L2 JAR paths |
| `--classpath-dir <path>` | — | Directory scanned recursively for `*.jar` |
| `--sbom <path>` | — | SBOM file (CycloneDX JSON/XML or SPDX JSON) |
| `--sbom-primary <g:a>` | — | SBOM component to use as L1 |
| `--sbom-cache <dir>` | `~/.cache/vuln-intel/jars` | JAR download cache directory |
| `--algo <cha\|0cfa>` | `cha` | Call-graph algorithm |
| `--max-depth <n>` | `15` | BFS depth limit |
| `--noise-threshold <f>` | `0.20` | Minimum path score to report |
| `--max-traces <n>` | `5` | Max reachable entry methods to report |
| `--serve <port>` | — | Start daemon on this port |

---

## Integration with vuln-intel

wala-runner is invoked automatically by `services/analysis/wala_analyzer.py`
as a fallback when SootUp hits TypeAssigner failures. Configure via `.env`:

```
WALA_DAEMON_URL=http://localhost:7071
WALA_MAX_HEAP=3g
ANALYSIS_DAEMON_THREADS=4
```

Start both analysis daemons:
```bash
./scripts/start_analysis_daemons.sh      # Linux/macOS
.\scripts\start_analysis_daemons.ps1     # Windows
```
