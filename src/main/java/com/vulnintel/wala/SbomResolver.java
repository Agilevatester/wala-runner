package com.vulnintel.wala;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.*;
import java.util.*;
import java.util.logging.*;

/**
 * SbomResolver — parses CycloneDX (JSON/XML) and SPDX JSON SBOMs, resolves Maven
 * coordinates, and downloads JARs from Maven Central into a local cache directory.
 *
 * <p>Supported SBOM formats:
 * <ul>
 *   <li>CycloneDX JSON  — {@code components[].purl} where purl = {@code pkg:maven/GROUP/ARTIFACT@VERSION}</li>
 *   <li>CycloneDX XML   — {@code <component><purl>...</purl></component>}</li>
 *   <li>SPDX JSON       — {@code packages[].externalRefs[].referenceLocator} with category {@code PACKAGE-MANAGER}</li>
 * </ul>
 *
 * <p>Typical standalone usage:
 * <pre>
 *   java -jar wala-runner.jar \
 *     --sbom bom.json \
 *     --sbom-primary "org.example:my-app" \
 *     --target "com.example.Foo.bar"
 * </pre>
 *
 * <p>With an explicit L1 JAR (SBOM becomes L2 classpath only):
 * <pre>
 *   java -jar wala-runner.jar \
 *     --jar my-app.jar \
 *     --sbom bom.json \
 *     --target "com.example.Foo.bar"
 * </pre>
 *
 * <p>Daemon mode — include any of these fields in the POST /analyse JSON body:
 * <pre>
 *   "sbom_file":    "/abs/path/to/bom.json"
 *   "sbom_purls":   ["pkg:maven/org.foo/bar@1.0", ...]
 *   "sbom_primary": "org.foo:bar"          // pick L1 from SBOM when "jar" is absent
 *   "sbom_cache":   "/path/to/cache"       // override default cache dir
 * </pre>
 */
public class SbomResolver {

    private static final Logger LOG = Logger.getLogger(SbomResolver.class.getName());
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String MAVEN_CENTRAL = "https://repo1.maven.org/maven2/";

    // ── Maven coordinate ──────────────────────────────────────────────────────

    public static class MavenCoord {
        public final String group;
        public final String artifact;
        public final String version;

        public MavenCoord(String group, String artifact, String version) {
            this.group    = group;
            this.artifact = artifact;
            this.version  = version;
        }

        /**
         * Returns true if this coordinate matches a {@code group:artifact} or
         * {@code group:artifact:version} identifier string.
         */
        public boolean matches(String primary) {
            if (primary == null || primary.isEmpty()) return false;
            String[] parts = primary.split(":", -1);
            if (parts.length >= 2) {
                return group.equals(parts[0]) && artifact.equals(parts[1]);
            }
            return artifact.equals(primary) || (group + ":" + artifact).equals(primary);
        }

        /** Relative path under the cache root: {@code group/path/artifact/version}. */
        public String cacheKey() {
            return group.replace('.', '/') + "/" + artifact + "/" + version;
        }

        public String jarFileName() {
            return artifact + "-" + version + ".jar";
        }

        public String mavenCentralUrl() {
            return MAVEN_CENTRAL + cacheKey() + "/" + jarFileName();
        }

        @Override
        public String toString() {
            return group + ":" + artifact + ":" + version;
        }
    }

    // ── SBOM parsing ──────────────────────────────────────────────────────────

    /**
     * Parse an SBOM file and return all Maven coordinates found within it.
     *
     * <p>Format is auto-detected:
     * <ul>
     *   <li>{@code *.xml}         → CycloneDX XML</li>
     *   <li>{@code *.json} with {@code bomFormat} or {@code components} → CycloneDX JSON</li>
     *   <li>{@code *.json} with {@code spdxVersion} or {@code packages}  → SPDX JSON</li>
     * </ul>
     */
    public static List<MavenCoord> parseSbom(Path sbomPath) throws Exception {
        String name = sbomPath.getFileName().toString().toLowerCase();
        if (name.endsWith(".xml")) {
            return parseCycloneDxXml(sbomPath);
        }
        JsonNode root = JSON.readTree(sbomPath.toFile());
        if (root.has("bomFormat") || root.has("components")) {
            return parseCycloneDxJson(root);
        }
        if (root.has("spdxVersion") || root.has("packages")) {
            return parseSpdxJson(root);
        }
        throw new IllegalArgumentException(
            "Unrecognised SBOM format (expected CycloneDX JSON/XML or SPDX JSON): " + sbomPath);
    }

    /** Parse a list of raw purl strings (e.g. supplied inline in daemon request). */
    public static List<MavenCoord> parsePurls(Iterable<String> purls) {
        List<MavenCoord> coords = new ArrayList<>();
        for (String purl : purls) {
            MavenCoord c = parsePurl(purl);
            if (c != null) coords.add(c);
        }
        return coords;
    }

    private static List<MavenCoord> parseCycloneDxJson(JsonNode root) {
        List<MavenCoord> coords = new ArrayList<>();
        JsonNode components = root.path("components");
        if (!components.isArray()) return coords;
        for (JsonNode comp : components) {
            MavenCoord c = parsePurl(comp.path("purl").asText(""));
            if (c != null) coords.add(c);
        }
        return coords;
    }

    private static List<MavenCoord> parseCycloneDxXml(Path xmlPath) throws Exception {
        List<MavenCoord> coords = new ArrayList<>();
        Document doc = DocumentBuilderFactory.newInstance()
                .newDocumentBuilder().parse(xmlPath.toFile());
        NodeList purls = doc.getElementsByTagName("purl");
        for (int i = 0; i < purls.getLength(); i++) {
            MavenCoord c = parsePurl(purls.item(i).getTextContent().trim());
            if (c != null) coords.add(c);
        }
        return coords;
    }

    private static List<MavenCoord> parseSpdxJson(JsonNode root) {
        List<MavenCoord> coords = new ArrayList<>();
        JsonNode packages = root.path("packages");
        if (!packages.isArray()) return coords;
        for (JsonNode pkg : packages) {
            JsonNode refs = pkg.path("externalRefs");
            if (!refs.isArray()) continue;
            for (JsonNode ref : refs) {
                String cat     = ref.path("referenceCategory").asText("");
                String locator = ref.path("referenceLocator").asText("");
                if ("PACKAGE-MANAGER".equalsIgnoreCase(cat) && locator.startsWith("pkg:maven/")) {
                    MavenCoord c = parsePurl(locator);
                    if (c != null) coords.add(c);
                }
            }
        }
        return coords;
    }

    /**
     * Parse a Package URL of the form {@code pkg:maven/GROUP/ARTIFACT@VERSION}.
     * In purl, the group uses '/' as separator (dots in Maven groupId).
     * Returns null for non-Maven or malformed purls.
     */
    public static MavenCoord parsePurl(String purl) {
        if (purl == null || !purl.startsWith("pkg:maven/")) return null;
        try {
            String rest = purl.substring("pkg:maven/".length());
            int q = rest.indexOf('?'); if (q >= 0) rest = rest.substring(0, q);
            int h = rest.indexOf('#'); if (h >= 0) rest = rest.substring(0, h);

            int at = rest.lastIndexOf('@');
            if (at < 0) return null;
            String version = rest.substring(at + 1).trim();
            String ga      = rest.substring(0, at);

            int slash = ga.lastIndexOf('/');
            if (slash < 0) return null;
            String group    = ga.substring(0, slash).replace('/', '.').trim();
            String artifact = ga.substring(slash + 1).trim();

            if (group.isEmpty() || artifact.isEmpty() || version.isEmpty()) return null;
            return new MavenCoord(group, artifact, version);
        } catch (Exception e) {
            return null;
        }
    }

    // ── JAR resolution & download ─────────────────────────────────────────────

    /**
     * Download all coordinates to the cache directory (if not already cached).
     * Returns paths to all successfully resolved JARs.
     * Failed downloads are logged and skipped — they do not abort the list.
     */
    public static List<Path> resolveJars(List<MavenCoord> coords, Path cacheDir) throws IOException {
        Files.createDirectories(cacheDir);
        List<Path> jars = new ArrayList<>();
        for (MavenCoord coord : coords) {
            try {
                Path jar = resolveJar(coord, cacheDir);
                if (jar != null) jars.add(jar);
            } catch (Exception e) {
                LOG.warning("Failed to resolve " + coord + ": " + e.getMessage());
            }
        }
        return jars;
    }

    /**
     * Download a single JAR from Maven Central, using the cache.
     * Returns null if the artifact is not found (HTTP 404).
     * Throws {@link IOException} on network errors.
     */
    public static Path resolveJar(MavenCoord coord, Path cacheDir) throws Exception {
        Path jarPath = cacheDir.resolve(coord.cacheKey()).resolve(coord.jarFileName());
        if (Files.exists(jarPath) && Files.size(jarPath) > 0) {
            LOG.fine("Cache hit: " + coord);
            return jarPath;
        }
        Files.createDirectories(jarPath.getParent());

        String urlStr = coord.mavenCentralUrl();
        LOG.info("Downloading " + coord + " from " + urlStr);

        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        conn.setConnectTimeout(15_000);
        conn.setReadTimeout(120_000);
        conn.setRequestProperty("User-Agent", "vuln-intel-wala-runner/1.0");

        int status = conn.getResponseCode();
        if (status == 404) {
            LOG.warning("Not found on Maven Central: " + urlStr);
            return null;
        }
        if (status != 200) {
            throw new IOException("HTTP " + status + " downloading " + urlStr);
        }

        Path tmp = jarPath.resolveSibling(coord.jarFileName() + ".tmp");
        try (InputStream in  = conn.getInputStream();
             OutputStream out = Files.newOutputStream(tmp)) {
            in.transferTo(out);
        }
        Files.move(tmp, jarPath, StandardCopyOption.ATOMIC_MOVE);
        LOG.info("Cached " + coord + " → " + jarPath);
        return jarPath;
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    /**
     * Default cache directory: {@code ~/.cache/vuln-intel/jars}.
     * Falls back to {@code $TMPDIR/vuln-intel-jars} if the home directory is unavailable.
     */
    public static Path defaultCacheDir() {
        String home = System.getProperty("user.home");
        if (home != null && !home.isEmpty()) {
            return Paths.get(home, ".cache", "vuln-intel", "jars");
        }
        return Paths.get(System.getProperty("java.io.tmpdir", "/tmp"), "vuln-intel-jars");
    }

    /**
     * Split the list into [L1, L2] given a primary identifier string.
     * Index 0 of the result is the L1 path (may be null if not found).
     * Index 1 of the result is the list of L2 paths.
     *
     * @param coords  all coordinates from the SBOM
     * @param jars    resolved local JAR paths in the same order as coords
     * @param primary {@code group:artifact} or {@code group:artifact:version}
     * @return two-element array: [{@code Path} L1 or null, {@code List<Path>} L2]
     */
    public static Object[] splitL1L2(List<MavenCoord> coords, List<Path> jars, String primary) {
        Path l1 = null;
        List<Path> l2 = new ArrayList<>();
        for (int i = 0; i < coords.size() && i < jars.size(); i++) {
            if (l1 == null && coords.get(i).matches(primary)) {
                l1 = jars.get(i);
            } else {
                l2.add(jars.get(i));
            }
        }
        return new Object[]{ l1, l2 };
    }
}
