package com.vulnintel.wala;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.classLoader.Language;
import com.ibm.wala.ipa.callgraph.AnalysisOptions;
import com.ibm.wala.ipa.callgraph.AnalysisScope;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.CallGraphBuilder;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.Entrypoint;
import com.ibm.wala.ipa.callgraph.cha.CHACallGraph;
import com.ibm.wala.ipa.callgraph.AnalysisCacheImpl;
import com.ibm.wala.ipa.callgraph.impl.DefaultEntrypoint;
import com.ibm.wala.ipa.callgraph.impl.Util;
import com.ibm.wala.ipa.cha.ClassHierarchy;
import com.ibm.wala.ipa.cha.ClassHierarchyFactory;
import com.ibm.wala.core.util.config.AnalysisScopeReader;
import com.ibm.wala.core.java11.Java9AnalysisScopeReader;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.types.MethodReference;
import com.ibm.wala.types.TypeName;
import com.ibm.wala.types.TypeReference;
import com.ibm.wala.core.util.strings.Atom;
import com.ibm.wala.ssa.DefaultIRFactory;

import java.util.*;
import java.util.concurrent.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import org.slf4j.LoggerFactory;

/**
 * WalaRunner — CLI entry point invoked by services/analysis/wala_analyzer.py.
 *
 * Produces the same JSON schema as SootUpRunner so the Python dispatcher can
 * treat both interchangeably or merge their results.
 *
 * CLI modes:
 *
 * Single-target:
 *   java -jar wala-runner.jar --jar /path/to.jar --target "com.example.Foo.bar"
 *
 * Multi-jar single-target:
 *   java -jar wala-runner.jar --jars-file jars.json --target "com.example.Foo.bar"
 *
 * Batch (build callgraph once, query N targets):
 *   java -jar wala-runner.jar --jar /path/to.jar --targets-file targets.json
 *
 * Batch + L2 classpath:
 *   java -jar wala-runner.jar --jar /path/to.jar \
 *       --classpath-file /path/classpath.json \   <- ["dep1.jar","dep2.jar",...]
 *       --classpath-dir /path/to/deps \           <- recursively adds **\/*.jar
 *       --targets-file targets.json
 *
 * Daemon mode:
 *
 *   java -jar wala-runner.jar --serve 7071
 *
 *   POST /analyse   Content-Type: application/json
 *   {
 *     "jar":       "/abs/path/to/dependent.jar",
 *     "classpath": ["/abs/path/dep1.jar"],   // optional L2 JARs
 *     "targets":   ["com.example.Foo.bar"],
 *     "max_depth": 10
 *   }
 *   -> {"batch":true,"results":{...}}
 *
 *   GET /health -> 200 {"status":"ok","contexts_cached":N}
 */
public class WalaRunner {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(WalaRunner.class);
    private static final int DEFAULT_MAX_DEPTH = 15;
    private static final double DEFAULT_NOISE_THRESHOLD = 0.20;
    private static final int DEFAULT_MAX_TRACES = 5;
    private static final int MAX_LOGGED_JAR_WARNINGS = 10;

    // Daemon context cache:
    private static final int MAX_CACHED_CONTEXTS = 20;

    /**
     * LRU cache: cacheKey → CompletableFuture<CallGraphContext>.
     * Access-ordered so the least-recently-used entry is evicted when the
     * cache reaches MAX_CACHED_CONTEXTS.
     */
    private static final LinkedHashMap<String, CompletableFuture<CallGraphContext>> CONTEXT_CACHE =
        new LinkedHashMap<>(MAX_CACHED_CONTEXTS + 4, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, CompletableFuture<CallGraphContext>> eldest) {
                return size() > MAX_CACHED_CONTEXTS;
            }
        };

    /** Deduplicates identical in-flight analysis requests. */
    private static final ConcurrentHashMap<String, CompletableFuture<ObjectNode>> PENDING_REQUESTS =
        new ConcurrentHashMap<>();

    /** Thread pool for context build + analysis inside the daemon. */
    private static final ExecutorService EXECUTOR = Executors.newFixedThreadPool(
        Integer.parseInt(System.getProperty("wala.daemon.threads", "4"))
    );

    // ── Prebuilt callgraph context ────────────────────────────────────────────

    /**
     * Holds the expensive precomputed callgraph state.
     * Build once per JAR via buildContext(), then query many targets cheaply via queryTarget().
     */
    static final class CallGraphContext {
        final AnalysisScope scope;
        final ClassHierarchy cha;
        final List<Entrypoint> entryPoints;
        final CallGraph cg;
        final Map<MethodReference, CGNode> cgNodeIndex;
        final String actualAlgo;
        final int appClassCount;
        final boolean forcedCha;

        CallGraphContext(AnalysisScope scope, ClassHierarchy cha,
                         List<Entrypoint> entryPoints, CallGraph cg,
                         Map<MethodReference, CGNode> cgNodeIndex,
                         String actualAlgo, int appClassCount, boolean forcedCha) {
            this.scope        = scope;
            this.cha          = cha;
            this.entryPoints  = entryPoints;
            this.cg           = cg;
            this.cgNodeIndex  = cgNodeIndex;
            this.actualAlgo   = actualAlgo;
            this.appClassCount = appClassCount;
            this.forcedCha    = forcedCha;
        }
    }

    static final class ResultOptions {
        final double noiseThreshold;
        final int maxTraces;
        final boolean suppressJdkBounce;
        final boolean primaryJarEntrypointsOnly;
        final boolean ignoreMissingClasspathJars;

        ResultOptions(double noiseThreshold, int maxTraces,
                      boolean suppressJdkBounce, boolean primaryJarEntrypointsOnly,
                      boolean ignoreMissingClasspathJars) {
            this.noiseThreshold = noiseThreshold;
            this.maxTraces = maxTraces;
            this.suppressJdkBounce = suppressJdkBounce;
            this.primaryJarEntrypointsOnly = primaryJarEntrypointsOnly;
            this.ignoreMissingClasspathJars = ignoreMissingClasspathJars;
        }
    }

    static final class ScoredPath {
        final List<CGNode> path;
        final double score;

        ScoredPath(List<CGNode> path, double score) {
            this.path = path;
            this.score = score;
        }
    }

    private static ResultOptions defaultResultOptions() {
        return new ResultOptions(DEFAULT_NOISE_THRESHOLD, DEFAULT_MAX_TRACES, true, true, false);
    }

    private static void logInfo(String message) {
        LOG.info(message);
    }

    private static void logWarn(String message) {
        LOG.warn(message);
    }

    private static void logWarn(String message, Throwable error) {
        LOG.warn(message, error);
    }

    private static void logError(String message, Throwable error) {
        LOG.error(message, error);
    }

    private static void validateJarReadable(String jarPath) throws IOException {
        File jarFile = new File(jarPath);
        if (!jarFile.exists()) {
            throw new IOException("JAR does not exist");
        }
        if (!jarFile.isFile()) {
            throw new IOException("Path is not a regular file");
        }
        try (JarFile jar = new JarFile(jarFile)) {
            byte[] buffer = new byte[8192];
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.isDirectory()) continue;
                try (InputStream in = jar.getInputStream(entry)) {
                    while (in.read(buffer) != -1) {
                        // Drain each entry so JarFile surfaces truncation/CRC issues early.
                    }
                }
            }
        }
    }

    private static List<String> sanitizeClasspathJars(List<String> classpathJars,
                                                      String requiredBy,
                                                      boolean ignoreMissingClasspathJars) throws IOException {
        if (classpathJars == null || classpathJars.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> valid = new ArrayList<>();
        int warned = 0;
        for (String jar : classpathJars) {
            if (jar == null || jar.trim().isEmpty()) {
                continue;
            }
            try {
                validateJarReadable(jar);
                valid.add(jar);
            } catch (IOException ex) {
                String reason = "Classpath jar '" + jar + "' is missing/unreadable; required by '" + requiredBy + "'";
                if (!ignoreMissingClasspathJars) {
                    throw new IOException(reason, ex);
                }
                warned++;
                if (warned <= MAX_LOGGED_JAR_WARNINGS) {
                    logWarn(reason + ". Ignoring because ignoreMissingClasspathJars=true", ex);
                }
            }
        }
        int skipped = classpathJars.size() - valid.size();
        if (skipped > warned) {
            logWarn("Skipped " + skipped + " unreadable/corrupted classpath jars; only the first "
                    + warned + " were logged individually");
        } else if (skipped > 0) {
            logWarn("Skipped " + skipped + " unreadable/corrupted classpath jars during scope build");
        }
        return valid;
    }

    /**
     * Build the analysis scope, class hierarchy, entry points, call graph, and node
     * index for the given JAR.  This is the expensive O(JAR_size) phase shared
     * across all targets in batch mode.
     *
     * @param jarPath       L1: the dependent JAR to analyse
     * @param algo          "cha" or "0cfa"
     * @param classpathJars L2: transitive dependency JARs (may be null or empty).
     *                      These are added to the analysis scope so WALA can resolve
     *                      cross-module method signatures without crashing. They are
     *                      added to the Application scope (same loader as L1), making
     *                      all referenced classes resolvable.
     * @return null if no public entry points are found.
     */
    static CallGraphContext buildContext(String jarPath, String algo,
                                        List<String> classpathJars,
                                        boolean primaryJarEntrypointsOnly,
                                        boolean ignoreMissingClasspathJars) throws Exception {
        long startedAt = System.nanoTime();
        validateJarReadable(jarPath);

        // Build classpath string: L1 JAR + optional L2 JARs (path-separator-joined)
        String fullClasspath = jarPath;
        List<String> sanitizedClasspath = sanitizeClasspathJars(
                classpathJars, jarPath, ignoreMissingClasspathJars);
        logInfo("Building context for primary jar '" + jarPath + "' with "
                + sanitizedClasspath.size() + " validated dependency jars"
                + (classpathJars == null ? "" : " (requested " + classpathJars.size() + ")")
                + ", algo=" + algo
                + ", primaryJarEntrypointsOnly=" + primaryJarEntrypointsOnly
                + ", ignoreMissingClasspathJars=" + ignoreMissingClasspathJars);
        if (!sanitizedClasspath.isEmpty()) {
            fullClasspath += File.pathSeparator + String.join(File.pathSeparator, sanitizedClasspath);
        }

        // 1. Build analysis scope (L1 + L2 all in Application scope)
        AnalysisScope scope = new Java9AnalysisScopeReader()
            .makeJavaBinaryAnalysisScope(fullClasspath, (File) null);

        // 2. Build class hierarchy
        ClassHierarchy cha = ClassHierarchyFactory.make(scope);

        Set<String> primaryJarClasses = primaryJarEntrypointsOnly
                ? loadPrimaryJarClasses(jarPath)
                : Collections.emptySet();

        // 3. Collect entry points — prefer only classes defined by the primary jar
        //    so dependency jars on the application classpath do not become roots.
        List<Entrypoint> entryPoints = new ArrayList<>();
        for (IClass cls : cha) {
            if (!cls.getClassLoader().getReference().equals(ClassLoaderReference.Application))
                continue;
            if (primaryJarEntrypointsOnly && !isPrimaryJarClass(cls, primaryJarClasses))
                continue;
            if (cls.isInterface() || cls.isAbstract()) continue;
            for (IMethod m : cls.getDeclaredMethods()) {
                if (m.isPublic() && !m.isAbstract() && !m.isNative() && !m.isSynthetic()) {
                    entryPoints.add(new DefaultEntrypoint(m, cha));
                    if (entryPoints.size() >= 2000) break;
                }
            }
            if (entryPoints.size() >= 2000) break;
        }

        if (entryPoints.isEmpty()) {
            return null;
        }

        // Count app classes to decide whether 0-CFA is feasible
        int appClassCount = 0;
        for (IClass cls : cha) {
            if (cls.getClassLoader().getReference().equals(ClassLoaderReference.Application))
                appClassCount++;
        }
        final int ZERO_CFA_CLASS_LIMIT = 800;
        String effectiveAlgo = algo;
        boolean forcedCha = false;
        if ("0cfa".equals(algo) && appClassCount > ZERO_CFA_CLASS_LIMIT) {
            effectiveAlgo = "cha";
            forcedCha = true;
            logWarn("Forcing algo=cha for primary jar '" + jarPath + "' because application class count "
                    + appClassCount + " exceeds limit " + ZERO_CFA_CLASS_LIMIT);
        }

        // 4. Build call graph
        AnalysisOptions options = new AnalysisOptions(scope, entryPoints);
        CallGraph cg;
        if ("cha".equals(effectiveAlgo)) {
            CHACallGraph chaCg = new CHACallGraph(cha);
            chaCg.init(entryPoints);
            cg = chaCg;
        } else {
            CallGraphBuilder<?> builder = Util.makeZeroCFABuilder(
                    Language.JAVA,
                    options,
                    new AnalysisCacheImpl(new DefaultIRFactory()),
                    cha);
            cg = builder.makeCallGraph(options, null);
        }

        // 5. Build MethodReference → CGNode index (O(|CG|), makes per-target lookup O(1))
        Map<MethodReference, CGNode> cgNodeIndex = new HashMap<>();
        for (CGNode n : cg) {
            cgNodeIndex.put(n.getMethod().getReference(), n);
        }

        long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt);
        logInfo("Built context for primary jar '" + jarPath + "' in " + elapsedMs + " ms"
                + " with " + appClassCount + " application classes, "
                + entryPoints.size() + " entry points, and algo=" + effectiveAlgo);

        return new CallGraphContext(scope, cha, entryPoints, cg, cgNodeIndex,
                effectiveAlgo, appClassCount, forcedCha);
    }

    private static Set<String> loadPrimaryJarClasses(String jarPath) throws IOException {
        Set<String> classes = new HashSet<>();
        try (JarFile jar = new JarFile(jarPath)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                if (entry.isDirectory() || !name.endsWith(".class")) {
                    continue;
                }
                if (name.contains("$")) {
                    name = name.substring(0, name.indexOf('$')) + ".class";
                }
                String fqdn = name.substring(0, name.length() - 6).replace('/', '.');
                classes.add(fqdn);
            }
        }
        return classes;
    }

    private static boolean isPrimaryJarClass(IClass cls, Set<String> primaryJarClasses) {
        String className = cls.getName().toString();
        if (className.startsWith("L")) {
            className = className.substring(1);
        }
        className = className.replace('/', '.');
        String outerBinaryName = className.contains("$")
                ? className.substring(0, className.indexOf('$'))
                : className;
        String fqdn = className.replace('$', '.');
        return primaryJarClasses.contains(className)
                || primaryJarClasses.contains(outerBinaryName)
                || primaryJarClasses.contains(fqdn);
    }

    private static List<String> discoverJarFiles(String rootDir) throws IOException {
        if (rootDir == null || rootDir.trim().isEmpty()) {
            return Collections.emptyList();
        }
        Path root = Path.of(rootDir);
        if (!Files.exists(root) || !Files.isDirectory(root)) {
            return Collections.emptyList();
        }
        try (java.util.stream.Stream<Path> stream = Files.walk(root)) {
            return stream
                    .filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().toLowerCase().endsWith(".jar"))
                    .map(path -> path.toFile().getAbsolutePath())
                    .sorted()
                    .collect(Collectors.toList());
        }
    }

    private static List<String> resolveClasspathJars(String classpathFile, List<String> classpathDirs)
            throws IOException {
        LinkedHashSet<String> jars = new LinkedHashSet<>();
        if (classpathFile != null) {
            jars.addAll(JSON.readValue(
                    new File(classpathFile),
                    JSON.getTypeFactory().constructCollectionType(List.class, String.class)));
        }
        if (classpathDirs != null) {
            for (String dir : classpathDirs) {
                jars.addAll(discoverJarFiles(dir));
            }
        }
        if (jars.isEmpty()) {
            return null;
        }
        logInfo("Resolved " + jars.size() + " classpath jar candidates");
        return new ArrayList<>(jars);
    }

    private static List<String> removePrimaryJarFromClasspath(String primaryJar, List<String> classpathJars) {
        if (primaryJar == null || classpathJars == null || classpathJars.isEmpty()) {
            return classpathJars;
        }
        String normalizedPrimary = new File(primaryJar).getAbsoluteFile().toPath().normalize().toString();
        List<String> filtered = new ArrayList<>();
        for (String jar : classpathJars) {
            if (jar == null || jar.trim().isEmpty()) {
                continue;
            }
            String normalizedCandidate = new File(jar).getAbsoluteFile().toPath().normalize().toString();
            if (!normalizedPrimary.equals(normalizedCandidate)) {
                filtered.add(jar);
            }
        }
        return filtered.isEmpty() ? null : filtered;
    }

    /** Backward-compatible overload — no L2 classpath. */
    static CallGraphContext buildContext(String jarPath, String algo) throws Exception {
        return buildContext(jarPath, algo, null, true, false);
    }

    /**
     * Query a single target FQDN against a prebuilt CallGraphContext.
     * This is the cheap per-target phase (O(target_lookup + BFS)).
     */
    static ObjectNode queryTarget(CallGraphContext ctx, String targetFqdn, int maxDepth,
                                  ResultOptions options) {
        // 6. Resolve target — two-stage strategy
        MethodReference targetRef  = resolveFqdn(ctx.cha, ctx.scope, targetFqdn);
        CGNode          targetNode = targetRef != null ? ctx.cgNodeIndex.get(targetRef) : null;

        if (targetNode == null) {
            targetNode = findTargetNode(ctx.cg, targetFqdn);
        }

        if (targetNode == null) {
            return errorNode("Target method not found in classpath: " + targetFqdn, ctx.actualAlgo);
        }

        // 7. Reverse BFS from target + collect paths from entry points
        ReverseReachability reverse = reverseReachability(ctx.cg, targetNode, maxDepth);
        List<ScoredPath> reachablePaths = new ArrayList<>();

        for (Entrypoint ep : ctx.entryPoints) {
            CGNode epNode = ctx.cgNodeIndex.get(ep.getMethod().getReference());
            if (epNode == null) continue;
            if (epNode.equals(targetNode)) continue;

            List<CGNode> path = buildPathToTarget(epNode, targetNode, reverse.nextHopToTarget);
            if (path != null) {
                List<CGNode> cleanedPath = trimTrailingNoise(path);
                double score = pathScore(cleanedPath, targetFqdn);
                reachablePaths.add(new ScoredPath(cleanedPath, score));
            }
        }

        String sourceLabel = "cha".equals(ctx.actualAlgo) ? "wala_cha" : "wala_0cfa";
        double confidence  = "cha".equals(ctx.actualAlgo) ? 0.70 : 0.85;

        ObjectNode result;
        if (!reachablePaths.isEmpty()) {
            result = reachableNode(targetFqdn, reachablePaths, sourceLabel, confidence, options);
        } else {
            result = notReachableNode(null, ctx.actualAlgo);
        }
        if (ctx.forcedCha) {
            result.put("algo_requested", "0cfa");
            result.put("algo_forced_cha_reason",
                    "JAR has " + ctx.appClassCount + " application classes (limit 800); "
                    + "0-CFA would OOM/timeout on JARs with shaded dependencies");
        }
        return result;
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /** Single-target analysis — builds context and queries one target. */
    static ObjectNode analyse(String jarPath, String targetFqdn, String algo, int maxDepth)
            throws Exception {
        return analyse(jarPath, targetFqdn, algo, maxDepth, null,
                new ResultOptions(DEFAULT_NOISE_THRESHOLD, DEFAULT_MAX_TRACES, true, true, false));
    }

    static ObjectNode analyse(String jarPath, String targetFqdn, String algo, int maxDepth,
                              List<String> classpathJars, ResultOptions options)
            throws Exception {
        CallGraphContext ctx = buildContext(jarPath, algo, classpathJars,
                options.primaryJarEntrypointsOnly, options.ignoreMissingClasspathJars);
        if (ctx == null) {
            return notReachableNode("No public entry points found in JAR", algo);
        }
        return queryTarget(ctx, targetFqdn, maxDepth, options);
    }

    /** Batch analysis — builds context ONCE, then queries all targets (no L2 classpath). */
    static ObjectNode analyseBatch(String jarPath, List<String> targets, String algo, int maxDepth)
            throws Exception {
        return analyseBatch(jarPath, targets, algo, maxDepth, null,
                new ResultOptions(DEFAULT_NOISE_THRESHOLD, DEFAULT_MAX_TRACES, true, true, false));
    }

    /**
     * Batch analysis with optional L2 classpath.
     * L2 JARs are added to the analysis scope so cross-module type references
     * (e.g. Keycloak classes referenced in IDS code) are visible to WALA.
     */
    static ObjectNode analyseBatch(String jarPath, List<String> targets, String algo, int maxDepth,
                                   List<String> classpathJars, ResultOptions options)
            throws Exception {
        ObjectNode batchResult = JSON.createObjectNode();
        batchResult.put("batch", true);
        ObjectNode results = batchResult.putObject("results");

        CallGraphContext ctx = buildContext(jarPath, algo, classpathJars,
                options.primaryJarEntrypointsOnly, options.ignoreMissingClasspathJars);
        if (ctx == null) {
            ObjectNode noEp = notReachableNode("No public entry points found in JAR", algo);
            for (String target : targets) {
                results.set(target, noEp.deepCopy());
            }
            return batchResult;
        }

        for (String target : targets) {
            try {
                results.set(target, queryTarget(ctx, target, maxDepth, options));
            } catch (Exception ex) {
                results.set(target, errorNode("Query failed: " + ex.getClass().getSimpleName()
                        + ": " + ex.getMessage(), ctx.actualAlgo));
            }
        }
        return batchResult;
    }

    // ── Daemon mode ───────────────────────────────────────────────────────────

    static ObjectNode analyseAcrossJars(List<String> jarPaths, String targetFqdn, String algo,
                                        int maxDepth, List<String> classpathJars,
                                        ResultOptions options) {
        ObjectNode batchResult = JSON.createObjectNode();
        batchResult.put("batch", true);
        batchResult.put("multi_jar", true);
        batchResult.put("target", targetFqdn);
        ObjectNode results = batchResult.putObject("results");

        for (String jarPath : jarPaths) {
            if (jarPath == null || jarPath.trim().isEmpty()) {
                continue;
            }
            try {
                results.set(jarPath, analyse(jarPath, targetFqdn, algo, maxDepth, classpathJars, options));
            } catch (Exception ex) {
                results.set(jarPath, errorNode(
                        "Analysis failed: " + ex.getClass().getSimpleName() + ": " + ex.getMessage(),
                        algo));
            }
        }
        return batchResult;
    }

    private static String contextCacheKey(String jarPath, List<String> classpath,
                                          boolean ignoreMissingClasspathJars) {
        if (classpath == null || classpath.isEmpty()) {
            return jarPath + "|ignoreMissing:" + ignoreMissingClasspathJars;
        }
        List<String> sorted = new ArrayList<>(classpath);
        Collections.sort(sorted);
        return jarPath + "|" + String.join("|", sorted)
                + "|ignoreMissing:" + ignoreMissingClasspathJars;
    }

    private static String requestKey(String jarPath, List<String> classpath,
                                     List<String> targets, int maxDepth,
                                     boolean ignoreMissingClasspathJars) {
        List<String> sortedTargets = new ArrayList<>(targets);
        Collections.sort(sortedTargets);
        return contextCacheKey(jarPath, classpath, ignoreMissingClasspathJars)
             + "||targets:" + String.join(",", sortedTargets)
             + "||depth:" + maxDepth;
    }

    /**
     * Get or build a CallGraphContext for the given jar+classpath via the LRU cache.
     * Concurrent callers for the same key share one CompletableFuture.
     */
    private static CompletableFuture<CallGraphContext> getOrBuildContext(
            String jarPath, List<String> classpath, String algo,
            boolean primaryJarEntrypointsOnly, boolean ignoreMissingClasspathJars) {

        String key = contextCacheKey(jarPath, classpath, ignoreMissingClasspathJars);

        synchronized (CONTEXT_CACHE) {
            CompletableFuture<CallGraphContext> existing = CONTEXT_CACHE.get(key);
            if (existing != null) {
                return existing;
            }
            CompletableFuture<CallGraphContext> future = new CompletableFuture<>();
            CONTEXT_CACHE.put(key, future);

            final String fJar    = jarPath;
            final List<String> fCp = classpath;
            final String fAlgo   = algo;
            final boolean fPrimaryOnly = primaryJarEntrypointsOnly;
            final boolean fIgnoreMissing = ignoreMissingClasspathJars;
            EXECUTOR.submit(() -> {
                try {
                    logInfo("Cache miss for context key '" + key + "'");
                    CallGraphContext ctx = buildContext(fJar, fAlgo, fCp, fPrimaryOnly, fIgnoreMissing);
                    future.complete(ctx);
                } catch (Throwable t) {
                    logError("Context build failed for primary jar '" + fJar + "'", t);
                    future.completeExceptionally(t);
                    synchronized (CONTEXT_CACHE) {
                        CONTEXT_CACHE.remove(key, future);
                    }
                }
            });

            return future;
        }
    }

    /**
     * Handle POST /analyse in the HTTP daemon.
     */
    private static void handleAnalyse(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendResponse(exchange, 405, "{\"error\":\"Method not allowed, use POST\"}");
            return;
        }

        byte[] bodyBytes;
        try (InputStream in = exchange.getRequestBody()) {
            bodyBytes = in.readAllBytes();
        }

        String jarPath;
        List<String> classpath;
        List<String> targets;
        int maxDepth;
        String algo;
        boolean ignoreMissingClasspathJars;
        try {
            ObjectNode req = (ObjectNode) JSON.readTree(bodyBytes);
            // "jar" is now optional when sbom_primary is supplied
            jarPath  = req.has("jar") ? req.get("jar").asText() : null;
            maxDepth = req.has("max_depth") ? req.get("max_depth").asInt(DEFAULT_MAX_DEPTH)
                                            : DEFAULT_MAX_DEPTH;
            algo     = req.has("algo") ? req.get("algo").asText("cha").toLowerCase() : "cha";
            ignoreMissingClasspathJars = req.has("ignore_missing_jars")
                    && req.get("ignore_missing_jars").asBoolean(false);
            targets  = new ArrayList<>();
            if (req.has("targets")) {
                for (com.fasterxml.jackson.databind.JsonNode el : req.get("targets")) targets.add(el.asText());
            }
            classpath = new ArrayList<>();
            if (req.has("classpath")) {
                for (com.fasterxml.jackson.databind.JsonNode el : req.get("classpath")) classpath.add(el.asText());
            }

            // ── SBOM resolution ───────────────────────────────────────────────
            if (req.has("sbom_file") || req.has("sbom_purls")) {
                String sbomCacheStr = req.has("sbom_cache") ? req.get("sbom_cache").asText() : null;
                java.nio.file.Path cacheDir = sbomCacheStr != null
                        ? java.nio.file.Paths.get(sbomCacheStr)
                        : SbomResolver.defaultCacheDir();

                List<SbomResolver.MavenCoord> coords;
                if (req.has("sbom_file")) {
                    coords = SbomResolver.parseSbom(
                            java.nio.file.Paths.get(req.get("sbom_file").asText()));
                } else {
                    List<String> purls = new ArrayList<>();
                    for (com.fasterxml.jackson.databind.JsonNode el : req.get("sbom_purls"))
                        purls.add(el.asText());
                    coords = SbomResolver.parsePurls(purls);
                }

                List<java.nio.file.Path> jars = SbomResolver.resolveJars(coords, cacheDir);
                String sbomPrimary = req.has("sbom_primary") ? req.get("sbom_primary").asText() : null;

                if (jarPath == null) {
                    if (sbomPrimary == null)
                        throw new IllegalArgumentException(
                            "sbom_primary is required when jar is not specified");
                    Object[] split = SbomResolver.splitL1L2(coords, jars, sbomPrimary);
                    java.nio.file.Path l1 = (java.nio.file.Path) split[0];
                    if (l1 == null)
                        throw new IllegalArgumentException(
                            "sbom_primary '" + sbomPrimary + "' not found in SBOM or failed to download");
                    jarPath = l1.toAbsolutePath().toString();
                    @SuppressWarnings("unchecked")
                    List<java.nio.file.Path> l2 = (List<java.nio.file.Path>) split[1];
                    for (java.nio.file.Path p : l2) classpath.add(p.toAbsolutePath().toString());
                } else {
                    for (java.nio.file.Path p : jars) classpath.add(p.toAbsolutePath().toString());
                }
            }
        } catch (Exception ex) {
            sendResponse(exchange, 400,
                "{\"error\":\"Bad request body: " + ex.getMessage().replace("\"", "'") + "\"}");
            return;
        }

        if (jarPath == null) {
            sendResponse(exchange, 400, "{\"error\":\"jar path is required (or provide sbom_file+sbom_primary)\"}");
            return;
        }

        if (targets.isEmpty()) {
            sendResponse(exchange, 400, "{\"error\":\"targets array is empty\"}");
            return;
        }

        logInfo("Received analyse request for primary jar '" + jarPath + "' with "
                + classpath.size() + " classpath jars, " + targets.size()
                + " targets, maxDepth=" + maxDepth + ", algo=" + algo
                + ", ignoreMissingClasspathJars=" + ignoreMissingClasspathJars);

        // Deduplication — piggyback on in-flight identical requests
        String reqKey = requestKey(jarPath, classpath, targets, maxDepth, ignoreMissingClasspathJars);
        CompletableFuture<ObjectNode> myFuture = new CompletableFuture<>();
        CompletableFuture<ObjectNode> existing = PENDING_REQUESTS.putIfAbsent(reqKey, myFuture);

        if (existing != null) {
            try {
                ObjectNode result = existing.get(600, TimeUnit.SECONDS);
                sendResponse(exchange, 200, JSON.writeValueAsString(result));
            } catch (TimeoutException ex) {
                sendResponse(exchange, 504, "{\"error\":\"Analysis timed out waiting for shared result\"}");
            } catch (Exception ex) {
                sendResponse(exchange, 500,
                    "{\"error\":\"Shared analysis failed: " + ex.getMessage().replace("\"","'") + "\"}");
            }
            return;
        }

        final String fJarPath   = jarPath;
        final List<String> fCp  = classpath;
        final List<String> fTgt = targets;
        final int fDepth        = maxDepth;
        final String fAlgo      = algo;
        final boolean fIgnoreMissing = ignoreMissingClasspathJars;

        EXECUTOR.submit(() -> {
            try {
                CompletableFuture<CallGraphContext> ctxFuture = getOrBuildContext(
                        fJarPath, fCp, fAlgo, defaultResultOptions().primaryJarEntrypointsOnly, fIgnoreMissing);
                CallGraphContext ctx = ctxFuture.get(600, TimeUnit.SECONDS);
                ResultOptions options = new ResultOptions(
                        DEFAULT_NOISE_THRESHOLD, DEFAULT_MAX_TRACES, true, true, fIgnoreMissing);
                ObjectNode result = runBatchOnContext(ctx, fTgt, fDepth, fAlgo, options);
                myFuture.complete(result);
            } catch (Throwable t) {
                logError("Background analysis failed for primary jar '" + fJarPath + "'", t);
                myFuture.completeExceptionally(t);
            } finally {
                PENDING_REQUESTS.remove(reqKey, myFuture);
            }
        });

        try {
            ObjectNode result = myFuture.get(600, TimeUnit.SECONDS);
            sendResponse(exchange, 200, JSON.writeValueAsString(result));
        } catch (TimeoutException ex) {
            sendResponse(exchange, 504, "{\"error\":\"Analysis timed out after 600s\"}");
        } catch (ExecutionException ex) {
            Throwable cause = ex.getCause();
            String msg = (cause != null ? cause.getMessage() : ex.getMessage());
            sendResponse(exchange, 500,
                "{\"error\":\"Analysis failed: " + (msg != null ? msg.replace("\"","'") : "unknown") + "\"}");
        } catch (Exception ex) {
            sendResponse(exchange, 500,
                "{\"error\":\"" + ex.getMessage().replace("\"","'") + "\"}");
        }
    }

    private static ObjectNode runBatchOnContext(CallGraphContext ctx,
            List<String> targets, int maxDepth, String algo, ResultOptions options) {
        ObjectNode batch = JSON.createObjectNode();
        batch.put("batch", true);
        ObjectNode results = batch.putObject("results");

        if (ctx == null) {
            ObjectNode noEp = notReachableNode("No public entry points found in JAR", algo);
            for (String t : targets) results.set(t, noEp.deepCopy());
            return batch;
        }
        for (String target : targets) {
            try {
                results.set(target, queryTarget(ctx, target, maxDepth, options));
            } catch (Exception ex) {
                results.set(target,
                    errorNode("Query failed: " + ex.getMessage(), ctx.actualAlgo));
            }
        }
        return batch;
    }

    private static void handleHealth(HttpExchange exchange) throws IOException {
        int cached;
        synchronized (CONTEXT_CACHE) { cached = CONTEXT_CACHE.size(); }
        sendResponse(exchange, 200,
            "{\"status\":\"ok\",\"contexts_cached\":" + cached + "}");
    }

    private static void sendResponse(HttpExchange exchange, int code, String body) {
        try {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            exchange.sendResponseHeaders(code, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        } catch (IOException ignored) {}
    }

    static void startDaemon(int port) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 64);
        server.createContext("/analyse", exchange -> {
            try {
                handleAnalyse(exchange);
            } catch (Exception ex) {
                try {
                    sendResponse(exchange, 500,
                        "{\"error\":\"Unhandled: " + ex.getMessage().replace("\"","'") + "\"}");
                } catch (Exception ignored) {}
            }
        });
        server.createContext("/health", exchange -> {
            try {
                handleHealth(exchange);
            } catch (Exception ignored) {}
        });
        server.setExecutor(null);
        server.start();
        System.err.println("[wala-daemon] Listening on port " + port
            + " — threads=" + System.getProperty("wala.daemon.threads", "4")
            + ", max_ctx_cache=" + MAX_CACHED_CONTEXTS);
        try {
            Thread.currentThread().join();
        } catch (InterruptedException ignored) {}
    }


    
    private static void writeError(String msg) throws Exception {
        System.out.println(JSON.writeValueAsString(errorNode(msg, "cha")));
    }

    private static boolean parseBooleanFlag(String[] args, int[] indexRef) {
        int next = indexRef[0] + 1;
        if (next >= args.length || args[next].startsWith("--")) {
            return true;
        }
        indexRef[0] = next;
        return Boolean.parseBoolean(args[next]);
    }

    // ── CLI entry point ───────────────────────────────────────────────────────

    public static void main(String[] args) throws Exception {
        Logger.getLogger("com.ibm.wala").setLevel(Level.SEVERE);
        Logger.getLogger("").setLevel(Level.SEVERE);

        String jarPath        = null;
        String jarsFile       = null;
        String targetFqdn     = null;
        String targetsFile    = null;
        String classpathFile  = null;
        List<String> classpathDirs = new ArrayList<>();
        String algo           = "cha";
        int    maxDepth       = DEFAULT_MAX_DEPTH;
        double noiseThreshold = DEFAULT_NOISE_THRESHOLD;
        int    maxTraces      = DEFAULT_MAX_TRACES;
        boolean suppressJdkBounce = true;
        boolean primaryJarEntrypointsOnly = true;
        boolean ignoreMissingClasspathJars = false;
        int    servePort      = -1;
        String sbomPath       = null;
        String sbomPrimary    = null;
        String sbomCacheDir   = null;

        for (int i = 0; i < args.length; i++) {
            int[] indexRef = new int[] { i };
            switch (args[i]) {
                case "--jar":            jarPath       = args[++i]; break;
                case "--jars-file":      jarsFile      = args[++i]; break;
                case "--target":         targetFqdn    = args[++i]; break;
                case "--targets-file":   targetsFile   = args[++i]; break;
                case "--classpath-file": classpathFile = args[++i]; break;
                case "--classpath-dir":  classpathDirs.add(args[++i]); break;
                case "--algo":           algo          = args[++i].toLowerCase(); break;
                case "--max-depth":      maxDepth      = Integer.parseInt(args[++i]); break;
                case "--noise-threshold": noiseThreshold = Double.parseDouble(args[++i]); break;
                case "--max-traces":      maxTraces = Integer.parseInt(args[++i]); break;
                case "--suppress-jdk-bounce":
                    suppressJdkBounce = parseBooleanFlag(args, indexRef);
                    i = indexRef[0];
                    break;
                case "--primary-jar-entrypoints-only":
                    primaryJarEntrypointsOnly = parseBooleanFlag(args, indexRef);
                    i = indexRef[0];
                    break;
                case "--ignore-missing-jars":
                    ignoreMissingClasspathJars = parseBooleanFlag(args, indexRef);
                    i = indexRef[0];
                    break;
                case "--serve":          servePort     = Integer.parseInt(args[++i]); break;
                // SBOM support
                case "--sbom":           sbomPath      = args[++i]; break;
                case "--sbom-primary":   sbomPrimary   = args[++i]; break;
                case "--sbom-cache":     sbomCacheDir  = args[++i]; break;
                default: break;
            }
        }

        // ── Daemon mode ──────────────────────────────────────────────────────
        if (servePort > 0) {
            startDaemon(servePort);
            return;
        }

        // ── SBOM resolution (CLI mode) ────────────────────────────────────────
        if (sbomPath != null) {
            try {
                java.nio.file.Path cacheDir = sbomCacheDir != null
                        ? java.nio.file.Paths.get(sbomCacheDir)
                        : SbomResolver.defaultCacheDir();
                List<SbomResolver.MavenCoord> coords = SbomResolver.parseSbom(
                        java.nio.file.Paths.get(sbomPath));
                List<java.nio.file.Path> jars = SbomResolver.resolveJars(coords, cacheDir);

                if (jarPath == null) {
                    // No explicit L1 — pick L1 from SBOM using --sbom-primary
                    if (sbomPrimary == null) {
                        writeError("--sbom-primary <group:artifact> is required when --jar is not specified");
                        System.exit(1);
                    }
                    Object[] split = SbomResolver.splitL1L2(coords, jars, sbomPrimary);
                    java.nio.file.Path l1 = (java.nio.file.Path) split[0];
                    if (l1 == null) {
                        writeError("SBOM primary '" + sbomPrimary + "' not found in SBOM or failed to download");
                        System.exit(1);
                    }
                    jarPath = l1.toAbsolutePath().toString();
                    @SuppressWarnings("unchecked")
                    List<java.nio.file.Path> l2 = (List<java.nio.file.Path>) split[1];
                    for (java.nio.file.Path p : l2) classpathDirs.add(p.getParent().toAbsolutePath().toString());
                } else {
                    // Explicit L1 — all SBOM JARs go to L2 classpath
                    for (java.nio.file.Path p : jars) classpathDirs.add(p.getParent().toAbsolutePath().toString());
                }
            } catch (Exception ex) {
                writeError("SBOM resolution failed: " + ex.getMessage());
                System.exit(1);
            }
        }

        // ── CLI mode ─────────────────────────────────────────────────────────
        if ((jarPath == null && jarsFile == null) || (targetFqdn == null && targetsFile == null)) {
            writeError("Missing required arguments: (--jar or --jars-file or --sbom+--sbom-primary) and (--target or --targets-file)");
            System.exit(1);
        }

        if (jarsFile != null && targetsFile != null) {
            writeError("Unsupported argument combination: --jars-file may only be used with --target");
            System.exit(1);
        }

        // Resolve optional L2 classpath from explicit JSON entries and/or recursive directories.
        List<String> classpathJars = resolveClasspathJars(classpathFile, classpathDirs);
        if (jarPath != null) {
            classpathJars = removePrimaryJarFromClasspath(jarPath, classpathJars);
        }
        logInfo("CLI resolved " + (classpathJars == null ? 0 : classpathJars.size())
                + " candidate classpath jars after removing the primary jar");
        ResultOptions options = new ResultOptions(
                noiseThreshold,
                Math.max(1, maxTraces),
                suppressJdkBounce,
                primaryJarEntrypointsOnly,
                ignoreMissingClasspathJars);

        try {
            if (jarsFile != null) {
                List<String> jars = JSON.readValue(
                        new File(jarsFile),
                        JSON.getTypeFactory().constructCollectionType(List.class, String.class));
                ObjectNode result = analyseAcrossJars(jars, targetFqdn, algo, maxDepth, classpathJars, options);
                System.out.println(JSON.writeValueAsString(result));
            } else if (targetsFile != null) {
                List<String> targets = JSON.readValue(
                        new File(targetsFile),
                        JSON.getTypeFactory().constructCollectionType(List.class, String.class));
                ObjectNode result = analyseBatch(jarPath, targets, algo, maxDepth, classpathJars, options);
                System.out.println(JSON.writeValueAsString(result));
            } else {
                ObjectNode result = analyse(jarPath, targetFqdn, algo, maxDepth, classpathJars, options);
                System.out.println(JSON.writeValueAsString(result));
            }
        } catch (Exception ex) {
            writeError("Analysis failed: " + ex.getClass().getSimpleName() + ": " + ex.getMessage());
            System.exit(0);
        }
    }

    // ── Target node lookup ───────────────────────────────────────────────────

    private static CGNode findTargetNode(CallGraph cg, String targetFqdn) {
        TargetSpec spec = parseTargetSpec(targetFqdn);
        if (spec == null) return null;

        CGNode fallback = null;
        for (CGNode n : cg) {
            IMethod m = n.getMethod();
            String rawCls = m.getDeclaringClass().getName().toString();
            String dotCls = rawCls.startsWith("L") ? rawCls.substring(1) : rawCls;
            dotCls = dotCls.replace('/', '.').replace('$', '.');

            boolean classMatch = dotCls.equals(spec.classFqdn)
                    || dotCls.replace('$', '.').equals(spec.classFqdn);
            if (classMatch
                    && m.getName().toString().equals(spec.methodName)
                    && matchesTargetSignature(m, spec)) {
                if (fallback == null) {
                    fallback = n;
                }
                if (spec.hasParams()) {
                    return n;
                }
            }
        }
        return fallback;
    }

    // ── Call-path quality scoring ─────────────────────────────────────────────

    /** JDK prefixes that indicate "bounce" hops — mirrors callpath_scorer.py. */
    private static final List<String> JDK_PREFIXES = Arrays.asList(
        "java.", "javax.", "jdk.", "sun.", "com.sun.",
        "org.ietf.jgss.", "org.omg.", "org.w3c.", "org.xml.", "jdk.internal."
    );

    private static final List<String> REFLECTION_PREFIXES = Arrays.asList(
        "java.lang.reflect.", "java.lang.invoke.",
        "sun.reflect.", "jdk.internal.reflect."
    );

    /** Logging-framework internals — frequent phantom CHA edges. */
    private static final List<String> LOGGING_PREFIXES = Arrays.asList(
        "org.slf4j.", "ch.qos.logback.", "org.apache.logging.",
        "org.apache.log4j.", "org.apache.commons.logging."
    );

    private static final Set<String> NOISE_METHODS = new HashSet<>(Arrays.asList(
        "toString", "hashCode", "equals", "compareTo", "compareToIgnoreCase",
        "println", "print", "printf", "format",
        "valueOf", "append", "charAt", "substring", "length", "isEmpty",
        "<clinit>", "<init>",
        "finalize", "clone", "wait", "notify", "notifyAll",
        "getClass", "getSimpleName", "getName",
        "write", "flush", "close",
        "run", "call", "execute",
        // Java serialization callbacks — almost always noise in reachability paths
        "readObject", "writeObject", "readResolve", "writeReplace", "readObjectNoData",
        // CGLib proxy dispatch
        "invoke", "invokeSuper", "intercept"
    ));

    /**
     * Score a call path — higher is cleaner/more meaningful.
     * Mirrors the Python callpath_scorer.score_path() rubric so the Java runner
     * pre-selects the best path before serialisation, reducing noise sent over
     * the wire and stored in the DB.
     */
    private static double pathScore(List<CGNode> path, String targetFqdn) {
        if (path == null || path.isEmpty()) return 0.0;
        double score = 0.50;
        int n = path.size();
        int jdkCount = 0, reflCount = 0, loggingCount = 0,
            syntheticCount = 0, noiseCount = 0, samePkgCount = 0;
        String targetTop = topPackage(targetFqdn, 2);

        for (CGNode node : path) {
            String fqdn   = nodeToFqdn(node);
            String method = node.getMethod().getName().toString();
            if (isJdkFqdn(fqdn))        jdkCount++;
            if (isReflectionFqdn(fqdn)) reflCount++;
            if (isLoggingFqdn(fqdn))    loggingCount++;
            if (isSyntheticMethod(fqdn, method)) syntheticCount++;
            if (NOISE_METHODS.contains(method))  noiseCount++;
            if (!targetTop.isEmpty() && fqdn.startsWith(targetTop)) samePkgCount++;
        }

        score -= 0.05 * jdkCount;
        score -= 0.05 * reflCount;
        score -= 0.05 * loggingCount;   // logging internals treated same as JDK bounce
        score -= 0.08 * syntheticCount; // proxy/lambda — strong signal for spurious CHA edge
        score -= 0.03 * noiseCount;
        if (jdkCount == n) score -= 0.10;
        if (!targetTop.isEmpty() && samePkgCount == 0) score -= 0.05;
        if (n <= 2)        score += 0.10;
        else if (n <= 4)   score += 0.05;
        score += 0.05 * Math.min(samePkgCount, 3);

        return Math.max(0.0, Math.min(1.0, score));
    }

    private static double roundScore(double score) {
        return Math.round(score * 1000.0) / 1000.0;
    }

    private static boolean isLoggingFqdn(String fqdn) {
        for (String p : LOGGING_PREFIXES) {
            if (fqdn.startsWith(p)) return true;
        }
        return false;
    }

    /**
     * Returns true for compiler-generated or proxy methods/classes:
     *  - lambda desugared:  lambda$methodName$0
     *  - inner-class bridge: access$000
     *  - Spring CGLIB proxy: Foo$$EnhancerBySpringCGLIB$$...
     *  - JDK dynamic proxy:  $Proxy0
     */
    private static boolean isSyntheticMethod(String fqdn, String method) {
        if (method.startsWith("lambda$") || method.startsWith("access$")) return true;
        // Class portion of the FQDN
        int dot = fqdn.lastIndexOf('.');
        String cls = dot >= 0 ? fqdn.substring(0, dot) : fqdn;
        return cls.contains("$$")
            || cls.contains("$EnhancerBy")
            || cls.contains("$FastClassBy")
            || cls.contains("$Proxy");
    }

    private static boolean isJdkFqdn(String fqdn) {
        for (String p : JDK_PREFIXES) {
            if (fqdn.startsWith(p)) return true;
        }
        return false;
    }

    private static boolean isReflectionFqdn(String fqdn) {
        for (String p : REFLECTION_PREFIXES) {
            if (fqdn.startsWith(p)) return true;
        }
        return false;
    }

    private static String topPackage(String fqdn, int depth) {
        if (fqdn == null || fqdn.isEmpty()) {
            return "";
        }
        String[] parts = fqdn.split("\\.");
        if (parts.length == 0) {
            return "";
        }
        if (parts.length <= depth) {
            return fqdn;
        }
        return String.join(".", Arrays.copyOfRange(parts, 0, depth));
    }

    private static List<CGNode> trimTrailingNoise(List<CGNode> path) {
        if (path == null || path.size() <= 2) {
            return path;
        }
        List<CGNode> trimmed = new ArrayList<>(path);
        while (trimmed.size() > 2) {
            CGNode candidate = trimmed.get(trimmed.size() - 2);
            String fqdn = nodeToFqdn(candidate);
            String method = candidate.getMethod().getName().toString();
            if (isJdkFqdn(fqdn) || NOISE_METHODS.contains(method)) {
                trimmed.remove(trimmed.size() - 2);
            } else {
                break;
            }
        }
        return trimmed;
    }

    // ── BFS ──────────────────────────────────────────────────────────────────

    private static final class ReverseReachability {
        private final Map<CGNode, CGNode> nextHopToTarget;

        private ReverseReachability(Map<CGNode, CGNode> nextHopToTarget) {
            this.nextHopToTarget = nextHopToTarget;
        }
    }

    private static ReverseReachability reverseReachability(
            CallGraph cg, CGNode target, int maxDepth) {

        Map<CGNode, CGNode> nextHopToTarget = new HashMap<>();
        Map<CGNode, Integer> distance = new HashMap<>();
        Deque<CGNode> queue = new ArrayDeque<>();

        queue.add(target);
        distance.put(target, 0);
        nextHopToTarget.put(target, null);

        while (!queue.isEmpty()) {
            CGNode cur = queue.poll();
            int curDist = distance.get(cur);
            if (curDist >= maxDepth) continue;

            Iterator<CGNode> preds = cg.getPredNodes(cur);
            while (preds.hasNext()) {
                CGNode pred = preds.next();
                if (distance.containsKey(pred)) continue;
                distance.put(pred, curDist + 1);
                nextHopToTarget.put(pred, cur);
                queue.add(pred);
            }
        }

        return new ReverseReachability(nextHopToTarget);
    }

    private static List<CGNode> buildPathToTarget(
            CGNode start, CGNode target,
            Map<CGNode, CGNode> nextHopToTarget) {

        if (start.equals(target)) {
            return Collections.singletonList(start);
        }
        if (!nextHopToTarget.containsKey(start)) {
            return null;
        }

        List<CGNode> path = new ArrayList<>();
        Set<CGNode> seen = new HashSet<>();
        CGNode cur = start;

        while (cur != null) {
            if (!seen.add(cur)) return null;
            path.add(cur);
            if (cur.equals(target)) return path;
            cur = nextHopToTarget.get(cur);
        }
        return null;
    }

    // ── FQDN resolution ──────────────────────────────────────────────────────

    private static MethodReference resolveFqdn(ClassHierarchy cha, AnalysisScope scope, String fqdn) {
        TargetSpec spec = parseTargetSpec(fqdn);
        if (spec == null) return null;

        String typeDescriptor = "L" + spec.classFqdn.replace('.', '/') + ";";
        TypeReference typeRef = TypeReference.find(ClassLoaderReference.Application,
                TypeName.string2TypeName(typeDescriptor));
        if (typeRef == null) return null;

        IClass cls = cha.lookupClass(typeRef);
        if (cls == null) return null;

        Atom nameAtom = Atom.findOrCreateUnicodeAtom(spec.methodName);

        for (IMethod m : cls.getAllMethods()) {
            if (m.getName().equals(nameAtom) && matchesTargetSignature(m, spec)) {
                return m.getReference();
            }
        }

        for (IMethod m : cls.getDeclaredMethods()) {
            if (m.getName().equals(nameAtom) && matchesTargetSignature(m, spec)) {
                return m.getReference();
            }
        }

        return null;
    }

    // ── JSON builders ─────────────────────────────────────────────────────────

    private static final class TargetSpec {
        private final String classFqdn;
        private final String methodName;
        private final List<String> paramDescriptors;

        private TargetSpec(String classFqdn, String methodName, List<String> paramDescriptors) {
            this.classFqdn        = classFqdn;
            this.methodName       = methodName;
            this.paramDescriptors = paramDescriptors;
        }

        private boolean hasParams() {
            return paramDescriptors != null;
        }
    }

    private static TargetSpec parseTargetSpec(String fqdn) {
        int parenIdx = fqdn.indexOf('(');
        String fqdnBase = parenIdx >= 0 ? fqdn.substring(0, parenIdx).trim() : fqdn.trim();
        int lastDot = fqdnBase.lastIndexOf('.');
        if (lastDot < 0) return null;

        String classPart = fqdnBase.substring(0, lastDot);
        String methodName = fqdnBase.substring(lastDot + 1);
        List<String> paramDescriptors = null;

        if (parenIdx >= 0) {
            int closeIdx = fqdn.lastIndexOf(')');
            if (closeIdx < parenIdx) return null;
            String rawParams = fqdn.substring(parenIdx + 1, closeIdx).trim();
            paramDescriptors = new ArrayList<>();
            if (!rawParams.isEmpty()) {
                for (String rawParam : splitParameterList(rawParams)) {
                    paramDescriptors.add(toJvmParamDescriptor(rawParam));
                }
            }
        }

        return new TargetSpec(classPart, methodName, paramDescriptors);
    }

    private static List<String> splitParameterList(String rawParams) {
        List<String> params = new ArrayList<>();
        int depth = 0;
        StringBuilder current = new StringBuilder();

        for (int i = 0; i < rawParams.length(); i++) {
            char ch = rawParams.charAt(i);
            if (ch == '<') depth++;
            else if (ch == '>') depth = Math.max(0, depth - 1);

            if (ch == ',' && depth == 0) {
                params.add(current.toString().trim());
                current.setLength(0);
                continue;
            }
            current.append(ch);
        }

        if (current.length() > 0) {
            params.add(current.toString().trim());
        }
        return params;
    }

    private static boolean matchesTargetSignature(IMethod method, TargetSpec spec) {
        if (!spec.hasParams()) return true;
        String selector = method.getSelector().toString();
        int open = selector.indexOf('(');
        int close = selector.indexOf(')');
        if (open < 0 || close < open) return false;

        String actualParams = selector.substring(open + 1, close);
        StringBuilder expected = new StringBuilder();
        for (String desc : spec.paramDescriptors) {
            expected.append(desc);
        }
        return actualParams.equals(expected.toString());
    }

    private static String toJvmParamDescriptor(String rawType) {
        String type = rawType.trim();
        int genericIdx = type.indexOf('<');
        if (genericIdx >= 0) {
            type = type.substring(0, genericIdx).trim();
        }
        if (type.endsWith("...")) {
            type = type.substring(0, type.length() - 3) + "[]";
        }

        int arrayDepth = 0;
        while (type.endsWith("[]")) {
            arrayDepth++;
            type = type.substring(0, type.length() - 2).trim();
        }

        String base;
        switch (type) {
            case "byte":    base = "B"; break;
            case "char":    base = "C"; break;
            case "double":  base = "D"; break;
            case "float":   base = "F"; break;
            case "int":     base = "I"; break;
            case "long":    base = "J"; break;
            case "short":   base = "S"; break;
            case "boolean": base = "Z"; break;
            case "void":    base = "V"; break;
            default:
                base = "L" + type.replace('.', '/').replace('$', '/') + ";";
                break;
        }

        StringBuilder desc = new StringBuilder();
        for (int i = 0; i < arrayDepth; i++) desc.append('[');
        desc.append(base);
        return desc.toString();
    }

    private static ObjectNode reachableNode(
            String targetFqdn, List<ScoredPath> allPaths,
            String source, double confidence, ResultOptions options) {
        List<ScoredPath> rankedPaths = rankPaths(allPaths, targetFqdn, options);
        ScoredPath first = rankedPaths.get(0);
        List<CGNode> firstPath = first.path;

        ObjectNode node = JSON.createObjectNode();
        node.put("reachable", true);
        node.put("analysis_source", source);
        node.put("confidence", confidence);
        node.putNull("error");
        node.put("sink_method", targetFqdn);
        node.put("call_path_score", roundScore(first.score));

        String entryFqdn = firstPath.isEmpty() ? "" : nodeToFqdn(firstPath.get(0));
        node.put("entry_method", entryFqdn);

        ArrayNode pathArr = node.putArray("call_path");
        for (CGNode n : firstPath) pathArr.add(nodeToStep(n));

        ArrayNode sinkToSourcePathArr = node.putArray("sink_to_source_call_path");
        for (int i = firstPath.size() - 1; i >= 0; i--)
            sinkToSourcePathArr.add(nodeToStep(firstPath.get(i)));

        ArrayNode reachArr = node.putArray("reachable_entry_methods");
        ArrayNode sourceArr = node.putArray("reachable_sources");
        Set<String> seenEntries = new HashSet<>();
        for (ScoredPath scoredPath : rankedPaths) {
            List<CGNode> path = scoredPath.path;
            if (path.isEmpty()) continue;
            String epFqdn = nodeToFqdn(path.get(0));
            if (seenEntries.contains(epFqdn)) continue;
            seenEntries.add(epFqdn);

            ObjectNode epNode = JSON.createObjectNode();
            epNode.put("fqdn", epFqdn);
            int epDot = epFqdn.lastIndexOf('.');
            epNode.put("class",  epDot >= 0 ? epFqdn.substring(0, epDot) : epFqdn);
            epNode.put("method", epDot >= 0 ? epFqdn.substring(epDot + 1) : "");
            epNode.put("call_path_score", roundScore(scoredPath.score));
            ArrayNode epPathArr = epNode.putArray("call_path");
            for (CGNode n : path) epPathArr.add(nodeToStep(n));
            ArrayNode epRevArr = epNode.putArray("sink_to_source_call_path");
            for (int i = path.size() - 1; i >= 0; i--) epRevArr.add(nodeToStep(path.get(i)));
            reachArr.add(epNode);
            sourceArr.add(epFqdn);
        }
        return node;
    }

    private static List<ScoredPath> rankPaths(List<ScoredPath> paths, String targetFqdn, ResultOptions options) {
        return paths.stream()
            .filter(sp -> sp.score >= options.noiseThreshold)
            .sorted((a, b) -> {
                int cmp = Double.compare(b.score, a.score);
                return cmp != 0 ? cmp : Integer.compare(a.path.size(), b.path.size());
            })
            .collect(java.util.stream.Collectors.toList());
    }

    // ── FQDN / step helpers ──────────────────────────────────────────────────

    private static String nodeToFqdn(CGNode n) {
        IMethod m = n.getMethod();
        String cls = m.getDeclaringClass().getName().toString()
                .substring(1).replace('/', '.');
        return cls + "." + m.getName().toString();
    }

    private static ObjectNode nodeToStep(CGNode n) {
        IMethod m   = n.getMethod();
        String  cls = m.getDeclaringClass().getName().toString()
                        .substring(1).replace('/', '.');
        String  method = m.getName().toString();
        ObjectNode step = JSON.createObjectNode();
        step.put("fqdn",   cls + "." + method);
        step.put("class",  cls);
        step.put("method", method);
        return step;
    }

    // ── Result-node builders ──────────────────────────────────────────────────

    private static ObjectNode notReachableNode(String reason, String algo) {
        ObjectNode node = JSON.createObjectNode();
        node.put("reachable",       false);
        node.putNull("entry_method");
        node.put("analysis_source", "wala_" + (algo != null ? algo.toLowerCase() : "cha"));
        node.put("confidence",      0.70);
        node.put("error",           reason != null ? reason : "not_reachable");
        node.putArray("call_path");
        node.putArray("sink_to_source_call_path");
        node.putArray("reachable_entry_methods");
        node.putArray("reachable_sources");
        return node;
    }

    private static ObjectNode errorNode(String msg, String algo) {
        ObjectNode node = JSON.createObjectNode();
        node.put("reachable",       false);
        node.putNull("entry_method");
        node.put("analysis_source", "error");
        node.put("confidence",      0.0);
        node.put("error",           msg);
        node.putArray("call_path");
        node.putArray("sink_to_source_call_path");
        node.putArray("reachable_entry_methods");
        node.putArray("reachable_sources");
        return node;
    }
}
