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

/**
 * WalaRunner — CLI entry point invoked by services/analysis/wala_analyzer.py.
 *
 * Produces the same JSON schema as SootUpRunner so the Python dispatcher can
 * treat both interchangeably or merge their results.
 *
 * ── CLI modes ──────────────────────────────────────────────────────────────
 *
 * Single-target:
 *   java -jar wala-runner.jar --jar /path/to.jar --target "com.example.Foo.bar"
 *
 * Batch (build callgraph once, query N targets):
 *   java -jar wala-runner.jar --jar /path/to.jar --targets-file targets.json
 *
 * Batch + L2 classpath:
 *   java -jar wala-runner.jar --jar /path/to.jar \
 *       --classpath-file /path/classpath.json \   <- ["dep1.jar","dep2.jar",...]
 *       --targets-file targets.json
 *
 * ── Daemon mode ────────────────────────────────────────────────────────────
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
    private static final int DEFAULT_MAX_DEPTH = 15;

    // ── Daemon context cache ─────────────────────────────────────────────────
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
                                        List<String> classpathJars) throws Exception {
        // Build classpath string: L1 JAR + optional L2 JARs (path-separator-joined)
        String fullClasspath = jarPath;
        if (classpathJars != null && !classpathJars.isEmpty()) {
            List<String> existing = classpathJars.stream()
                .filter(s -> s != null && new File(s).exists())
                .collect(Collectors.toList());
            if (!existing.isEmpty()) {
                fullClasspath += File.pathSeparator + String.join(File.pathSeparator, existing);
            }
        }

        // 1. Build analysis scope (L1 + L2 all in Application scope)
        AnalysisScope scope = new Java9AnalysisScopeReader()
            .makeJavaBinaryAnalysisScope(fullClasspath, (File) null);

        // 2. Build class hierarchy
        ClassHierarchy cha = ClassHierarchyFactory.make(scope);

        // 3. Collect entry points — only from the PRIMARY jar (L1) to keep analysis focused.
        //    We approximate L1 by counting app classes from jarPath alone first.
        //    Since WALA doesn't expose which JAR a class came from, we collect ALL
        //    application-loader public methods (the conservative approach).
        List<Entrypoint> entryPoints = new ArrayList<>();
        for (IClass cls : cha) {
            if (!cls.getClassLoader().getReference().equals(ClassLoaderReference.Application))
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

        return new CallGraphContext(scope, cha, entryPoints, cg, cgNodeIndex,
                effectiveAlgo, appClassCount, forcedCha);
    }

    /** Backward-compatible overload — no L2 classpath. */
    static CallGraphContext buildContext(String jarPath, String algo) throws Exception {
        return buildContext(jarPath, algo, null);
    }

    /**
     * Query a single target FQDN against a prebuilt CallGraphContext.
     * This is the cheap per-target phase (O(target_lookup + BFS)).
     */
    static ObjectNode queryTarget(CallGraphContext ctx, String targetFqdn, int maxDepth) {
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
        List<List<CGNode>> reachablePaths = new ArrayList<>();
        List<CGNode> bestPath = null;
        double bestScore = -1.0;

        for (Entrypoint ep : ctx.entryPoints) {
            CGNode epNode = ctx.cgNodeIndex.get(ep.getMethod().getReference());
            if (epNode == null) continue;
            if (epNode.equals(targetNode)) continue;

            List<CGNode> path = buildPathToTarget(epNode, targetNode, reverse.nextHopToTarget);
            if (path != null) {
                reachablePaths.add(path);
                // Prefer the path with the highest quality score (fewest JDK
                // bounce hops, shortest on tie) — mirrors callpath_scorer.best_path().
                double score = pathScore(path);
                if (score > bestScore || (score == bestScore && bestPath != null && path.size() < bestPath.size())) {
                    bestScore = score;
                    bestPath  = path;
                }
            }
        }

        String sourceLabel = "cha".equals(ctx.actualAlgo) ? "wala_cha" : "wala_0cfa";
        double confidence  = "cha".equals(ctx.actualAlgo) ? 0.70 : 0.85;

        ObjectNode result;
        if (!reachablePaths.isEmpty()) {
            result = reachableNode(targetFqdn, bestPath, reachablePaths, sourceLabel, confidence);
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
        CallGraphContext ctx = buildContext(jarPath, algo);
        if (ctx == null) {
            return notReachableNode("No public entry points found in JAR", algo);
        }
        return queryTarget(ctx, targetFqdn, maxDepth);
    }

    /** Batch analysis — builds context ONCE, then queries all targets (no L2 classpath). */
    static ObjectNode analyseBatch(String jarPath, List<String> targets, String algo, int maxDepth)
            throws Exception {
        return analyseBatch(jarPath, targets, algo, maxDepth, null);
    }

    /**
     * Batch analysis with optional L2 classpath.
     * L2 JARs are added to the analysis scope so cross-module type references
     * (e.g. Keycloak classes referenced in IDS code) are visible to WALA.
     */
    static ObjectNode analyseBatch(String jarPath, List<String> targets, String algo, int maxDepth,
                                   List<String> classpathJars)
            throws Exception {
        ObjectNode batchResult = JSON.createObjectNode();
        batchResult.put("batch", true);
        ObjectNode results = batchResult.putObject("results");

        CallGraphContext ctx = buildContext(jarPath, algo, classpathJars);
        if (ctx == null) {
            ObjectNode noEp = notReachableNode("No public entry points found in JAR", algo);
            for (String target : targets) {
                results.set(target, noEp.deepCopy());
            }
            return batchResult;
        }

        for (String target : targets) {
            try {
                results.set(target, queryTarget(ctx, target, maxDepth));
            } catch (Exception ex) {
                results.set(target, errorNode("Query failed: " + ex.getClass().getSimpleName()
                        + ": " + ex.getMessage(), ctx.actualAlgo));
            }
        }
        return batchResult;
    }

    // ── Daemon mode ───────────────────────────────────────────────────────────

    private static String contextCacheKey(String jarPath, List<String> classpath) {
        if (classpath == null || classpath.isEmpty()) {
            return jarPath;
        }
        List<String> sorted = new ArrayList<>(classpath);
        Collections.sort(sorted);
        return jarPath + "|" + String.join("|", sorted);
    }

    private static String requestKey(String jarPath, List<String> classpath,
                                     List<String> targets, int maxDepth) {
        List<String> sortedTargets = new ArrayList<>(targets);
        Collections.sort(sortedTargets);
        return contextCacheKey(jarPath, classpath)
             + "||targets:" + String.join(",", sortedTargets)
             + "||depth:" + maxDepth;
    }

    /**
     * Get or build a CallGraphContext for the given jar+classpath via the LRU cache.
     * Concurrent callers for the same key share one CompletableFuture.
     */
    private static CompletableFuture<CallGraphContext> getOrBuildContext(
            String jarPath, List<String> classpath, String algo) {

        String key = contextCacheKey(jarPath, classpath);

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
            EXECUTOR.submit(() -> {
                try {
                    CallGraphContext ctx = buildContext(fJar, fAlgo, fCp);
                    future.complete(ctx);
                } catch (Throwable t) {
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
        try {
            ObjectNode req = (ObjectNode) JSON.readTree(bodyBytes);
            jarPath  = req.required("jar").asText();
            maxDepth = req.has("max_depth") ? req.get("max_depth").asInt(DEFAULT_MAX_DEPTH)
                                            : DEFAULT_MAX_DEPTH;
            algo     = req.has("algo") ? req.get("algo").asText("cha").toLowerCase() : "cha";
            targets  = new ArrayList<>();
            if (req.has("targets")) {
                for (com.fasterxml.jackson.databind.JsonNode el : req.get("targets")) targets.add(el.asText());
            }
            classpath = new ArrayList<>();
            if (req.has("classpath")) {
                for (com.fasterxml.jackson.databind.JsonNode el : req.get("classpath")) classpath.add(el.asText());
            }
        } catch (Exception ex) {
            sendResponse(exchange, 400,
                "{\"error\":\"Bad request body: " + ex.getMessage().replace("\"", "'") + "\"}");
            return;
        }

        if (targets.isEmpty()) {
            sendResponse(exchange, 400, "{\"error\":\"targets array is empty\"}");
            return;
        }

        // Deduplication — piggyback on in-flight identical requests
        String reqKey = requestKey(jarPath, classpath, targets, maxDepth);
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

        EXECUTOR.submit(() -> {
            try {
                CompletableFuture<CallGraphContext> ctxFuture = getOrBuildContext(fJarPath, fCp, fAlgo);
                CallGraphContext ctx = ctxFuture.get(600, TimeUnit.SECONDS);
                ObjectNode result = runBatchOnContext(ctx, fTgt, fDepth, fAlgo);
                myFuture.complete(result);
            } catch (Throwable t) {
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
            List<String> targets, int maxDepth, String algo) {
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
                results.set(target, queryTarget(ctx, target, maxDepth));
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

    // ── CLI entry point ───────────────────────────────────────────────────────

    public static void main(String[] args) throws Exception {
        Logger.getLogger("com.ibm.wala").setLevel(Level.SEVERE);
        Logger.getLogger("").setLevel(Level.SEVERE);

        java.io.PrintStream originalStderr = System.err;
        System.setErr(new java.io.PrintStream(new java.io.OutputStream() {
            @Override public void write(int b) {}
            @Override public void write(byte[] b, int off, int len) {}
        }));

        String jarPath        = null;
        String targetFqdn     = null;
        String targetsFile    = null;
        String classpathFile  = null;
        String algo           = "cha";
        int    maxDepth       = DEFAULT_MAX_DEPTH;
        int    servePort      = -1;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--jar":            jarPath       = args[++i]; break;
                case "--target":         targetFqdn    = args[++i]; break;
                case "--targets-file":   targetsFile   = args[++i]; break;
                case "--classpath-file": classpathFile = args[++i]; break;
                case "--algo":           algo          = args[++i].toLowerCase(); break;
                case "--max-depth":      maxDepth      = Integer.parseInt(args[++i]); break;
                case "--serve":          servePort     = Integer.parseInt(args[++i]); break;
                default: break;
            }
        }

        // ── Daemon mode ──────────────────────────────────────────────────────
        if (servePort > 0) {
            System.setErr(originalStderr);
            startDaemon(servePort);
            return;
        }

        // ── CLI mode ─────────────────────────────────────────────────────────
        if (jarPath == null || (targetFqdn == null && targetsFile == null)) {
            System.setErr(originalStderr);
            writeError("Missing required arguments: --jar and (--target or --targets-file)");
            System.exit(1);
        }

        // Resolve optional L2 classpath from --classpath-file
        List<String> classpathJars = null;
        if (classpathFile != null) {
            classpathJars = JSON.readValue(
                new File(classpathFile),
                JSON.getTypeFactory().constructCollectionType(List.class, String.class));
        }

        try {
            if (targetsFile != null) {
                List<String> targets = JSON.readValue(
                        new File(targetsFile),
                        JSON.getTypeFactory().constructCollectionType(List.class, String.class));
                ObjectNode result = analyseBatch(jarPath, targets, algo, maxDepth, classpathJars);
                System.setErr(originalStderr);
                System.out.println(JSON.writeValueAsString(result));
            } else {
                ObjectNode result = analyse(jarPath, targetFqdn, algo, maxDepth);
                System.setErr(originalStderr);
                System.out.println(JSON.writeValueAsString(result));
            }
        } catch (Exception ex) {
            System.setErr(originalStderr);
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

    private static final Set<String> NOISE_METHODS = new HashSet<>(Arrays.asList(
        "toString", "hashCode", "equals", "compareTo", "compareToIgnoreCase",
        "println", "print", "printf", "format",
        "valueOf", "append", "charAt", "substring", "length", "isEmpty",
        "<clinit>", "<init>",
        "finalize", "clone", "wait", "notify", "notifyAll",
        "getClass", "getSimpleName", "getName",
        "write", "flush", "close",
        "run", "call", "execute"
    ));

    /**
     * Score a call path — higher is cleaner/more meaningful.
     * Mirrors the Python callpath_scorer.score_path() rubric so the Java runner
     * pre-selects the best path before serialisation, reducing noise sent over
     * the wire and stored in the DB.
     */
    private static double pathScore(List<CGNode> path) {
        if (path == null || path.isEmpty()) return 0.0;
        double score = 0.50;
        int n = path.size();
        int jdkCount = 0, reflCount = 0, noiseCount = 0;

        for (CGNode node : path) {
            String fqdn   = nodeToFqdn(node);
            String method = node.getMethod().getName().toString();
            boolean isJdk = false;
            for (String p : JDK_PREFIXES) { if (fqdn.startsWith(p)) { isJdk = true; break; } }
            boolean isRefl = false;
            for (String p : REFLECTION_PREFIXES) { if (fqdn.startsWith(p)) { isRefl = true; break; } }
            if (isJdk)   jdkCount++;
            if (isRefl)  reflCount++;
            if (NOISE_METHODS.contains(method)) noiseCount++;
        }

        score -= 0.05 * jdkCount;
        score -= 0.05 * reflCount;
        score -= 0.03 * noiseCount;
        if (jdkCount == n) score -= 0.10;
        if (n <= 2)        score += 0.10;
        else if (n <= 4)   score += 0.05;

        return Math.max(0.0, Math.min(1.0, score));
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
            String targetFqdn, List<CGNode> firstPath,
            List<List<CGNode>> allPaths,
            String source, double confidence) {

        ObjectNode node = JSON.createObjectNode();
        node.put("reachable", true);
        node.put("analysis_source", source);
        node.put("confidence", confidence);
        node.putNull("error");
        node.put("sink_method", targetFqdn);

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
        for (List<CGNode> path : allPaths) {
            if (path.isEmpty()) continue;
            String epFqdn = nodeToFqdn(path.get(0));
            if (seenEntries.contains(epFqdn)) continue;
            seenEntries.add(epFqdn);

            ObjectNode epNode = JSON.createObjectNode();
            epNode.put("fqdn", epFqdn);
            int epDot = epFqdn.lastIndexOf('.');
            epNode.put("class",  epDot >= 0 ? epFqdn.substring(0, epDot) : epFqdn);
            epNode.put("method", epDot >= 0 ? epFqdn.substring(epDot + 1) : "");
            ArrayNode epPathArr = epNode.putArray("call_path");
            for (CGNode n : path) epPathArr.add(nodeToStep(n));
            ArrayNode epRevArr = epNode.putArray("sink_to_source_call_path");
            for (int i = path.size() - 1; i >= 0; i--) epRevArr.add(nodeToStep(path.get(i)));
            reachArr.add(epNode);
            sourceArr.add(epFqdn);
        }
        return node;
    }

    // ── JSON output helpers ───────────────────────────────────────────────────

    private static void writeError(String msg) {
        try {
            ObjectNode node = JSON.createObjectNode();
            node.put("reachable",        false);
            node.putNull("entry_method");
            node.put("analysis_source",  "error");
            node.put("confidence",       0.0);
            node.put("error",            msg);
            node.putArray("call_path");
            node.putArray("sink_to_source_call_path");
            node.putArray("reachable_entry_methods");
            node.putArray("reachable_sources");
            System.out.println(JSON.writeValueAsString(node));
        } catch (Exception ignored) {
            System.out.println("{\"reachable\":false,\"error\":\"" + msg.replace("\"","'") + "\"}");
        }
    }

        private static String nodeToFqdn(CGNode n) {
        IMethod m = n.getMethod();
        String cls = m.getDeclaringClass().getName().toString()
                .substring(1).replace('/', '.').replace('$', '.');
        return cls + "." + m.getName().toString();
    }

    private static ObjectNode nodeToStep(CGNode n) {
        IMethod m = n.getMethod();
        String fqdn = nodeToFqdn(n);
        String cls  = m.getDeclaringClass().getName().toString()
                .substring(1).replace('/', '.').replace('$', '.');
        ObjectNode step = JSON.createObjectNode();
        step.put("fqdn",         fqdn);
        step.put("class",        cls);
        step.put("method",       m.getName().toString());
        step.put("subsignature", m.getSelector().toString());
        return step;
    }

    private static ObjectNode notReachableNode(String reason, String algo) {
        ObjectNode node = JSON.createObjectNode();
        node.put("reachable",        false);
        node.put("analysis_source",  "cha".equals(algo) ? "wala_cha" : "wala_0cfa");
        node.put("confidence",       0.0);
        if (reason != null) node.put("error", reason); else node.putNull("error");
        node.putArray("call_path");
        node.putArray("sink_to_source_call_path");
        node.putArray("reachable_entry_methods");
        node.putArray("reachable_sources");
        return node;
    }

    private static ObjectNode errorNode(String reason, String algo) {
        ObjectNode node = JSON.createObjectNode();
        node.put("reachable",       false);
        node.put("analysis_source", "error");
        node.put("confidence",      0.0);
        node.put("error",           reason != null ? reason : "unknown error");
        node.putArray("call_path");
        node.putArray("sink_to_source_call_path");
        node.putArray("reachable_entry_methods");
        node.putArray("reachable_sources");
        return node;
    }
}
