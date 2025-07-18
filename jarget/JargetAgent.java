
package jarget;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ForkJoinPool;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

import static jarget.JargetAgent.LogLevel.*;

/**
 * A secure Java agent that processes dependency comments similar to uv in Python.
 * <p>
 * This agent automatically resolves and downloads dependencies specified in Java source files
 * using special comment directives. It supports Maven dependencies, local JAR files,
 * JAR directories, and direct URL downloads with optional integrity verification.
 * </p>
 *
 * <h2>Supported Dependency Directives:</h2>
 * <ul>
 *   <li>{@code // @var name=value} - Defines a variable for substitution</li>
 *   <li>{@code // @dep groupId:artifactId:version} - Maven dependency</li>
 *   <li>{@code // @dep groupId:artifactId:version [md5|sha256:<checksum>]} - Maven dependency with checksum</li>
 *   <li>{@code // @jar /path/to/local.jar} - Local JAR file</li>
 *   <li>{@code // @dir /path/to/jar-directory} - Directory of JARs</li>
 *   <li>{@code // @url https://repo.com/lib.jar} - Direct URL download</li>
 * </ul>
 *
 * <h2>Configuration:</h2>
 * <p>The agent supports configuration via system properties or environment variables:</p>
 * <ul>
 *   <li>Log level: {@code jarget.log.level} or {@code JARGET_LOG_LEVEL}</li>
 *   <li>Trusted repos: {@code jarget.trusted.repos} or {@code JARGET_TRUSTED_REPOS}</li>
 *   <li>Download timeout: {@code jarget.download.timeout} or {@code JARGET_DOWNLOAD_TIMEOUT}</li>
 *   <li>Max download size: {@code jarget.max.download.size} or {@code JARGET_MAX_DOWNLOAD_SIZE}</li>
 *   <li>Cache directory: {@code jarget.cache.dir} or {@code JARGET_CACHE_DIR}</li>
 *   <li>Max retries: {@code jarget.max.retries} or {@code JARGET_MAX_RETRIES}</li>
 * </ul>
 *
 * <h2>Security Features:</h2>
 * <ul>
 *   <li>Repository whitelisting - only trusted Maven repositories allowed</li>
 *   <li>Checksum verification - SHA-256 and MD5 support</li>
 *   <li>Path traversal protection - prevents malicious local paths</li>
 *   <li>Input validation - validates Maven coordinates</li>
 *   <li>SSL/TLS verification - proper certificate validation</li>
 * </ul>
 *
 * @author Shiraz Kanga
 * @version 1.4
 * @since 1.0
 */
public class JargetAgent {
    public static final double JARGET_VERSION = 1.4;
    // Configuration constants
    private static final String TRUSTED_REPOS_PROP = "jarget.trusted.repos";
    private static final String TRUSTED_REPOS_ENV = "JARGET_TRUSTED_REPOS";
    private static final String LOG_LEVEL_PROP = "jarget.log.level";
    private static final String LOG_LEVEL_ENV = "JARGET_LOG_LEVEL";
    private static final String DOWNLOAD_TIMEOUT_PROP = "jarget.download.timeout";
    private static final String DOWNLOAD_TIMEOUT_ENV = "JARGET_DOWNLOAD_TIMEOUT";
    private static final String MAX_DOWNLOAD_SIZE_PROP = "jarget.max.download.size";
    private static final String MAX_DOWNLOAD_SIZE_ENV = "JARGET_MAX_DOWNLOAD_SIZE";
    private static final String CACHE_DIR_PROP = "jarget.cache.dir";
    private static final String CACHE_DIR_ENV = "JARGET_CACHE_DIR";
    private static final String MAX_RETRIES_PROP = "jarget.max.retries";
    private static final String MAX_RETRIES_ENV = "JARGET_MAX_RETRIES";
    private static final String PARALLEL_DOWNLOADS_PROP = "jarget.parallel.downloads";
    private static final String PARALLEL_DOWNLOADS_ENV = "JARGET_PARALLEL_DOWNLOADS";

    // Custom Logging Infrastructure
    enum LogLevel {
        SILENT,  // No output
        ERROR,   // Only errors
        INFO,    // Default: info and errors
        VERBOSE  // Verbose: all messages, including debug info
    }

    private static LogLevel currentLogLevel = LogLevel.INFO; // Default level

    private static void log(LogLevel level, String message) {
        switch (level) {
            case VERBOSE:
                if (currentLogLevel.ordinal() >= LogLevel.VERBOSE.ordinal())
                    System.out.printf("[JarGet] Debug: %s%n", message);
                break;
            case INFO:
                if (currentLogLevel.ordinal() >= LogLevel.INFO.ordinal())
                    System.out.printf("[JarGet] Info: %s%n", message);
                break;
            case ERROR:
                if (currentLogLevel.ordinal() >= ERROR.ordinal())
                    System.err.printf("[JarGet] ERROR: %s%n", message);
                break;
            case SILENT: break;
            default: break;
        }
    }

    private static void log(LogLevel level, String message, Throwable t) {
        log(level, message);
        if (currentLogLevel.ordinal() >= ERROR.ordinal()) {
            t.printStackTrace(System.err);
        }
    }

    // Configuration variables
    private static int downloadTimeoutSeconds = 30;
    private static long maxDownloadSize = 100 * 1024 * 1024; // 100MB
    private static int maxRetries = 3;
    private static int parallelDownloads = 4;
    private static Path cacheDir = null;

    // Dynamic trusted repositories
    private static Set<String> trustedRepos;

    // Keep references to JAR files to prevent them from being garbage collected
    private static final Set<JarFile> openJarFiles = ConcurrentHashMap.newKeySet();

    // Static initializer to register shutdown hook for cleanup.
    static {
        Runtime.getRuntime().addShutdownHook(new Thread(JargetAgent::cleanupResources));
    }

    /**
     * Immutable set of default trusted Maven repositories.
     * These are well-known, secure repositories that are safe to download from.
     * Additional repositories can be added via configuration.
     */
    private static final Set<String> TRUSTED_REPOS = new HashSet<>(Arrays.asList(
        "https://repo1.maven.org/maven2/",                                   // Maven Central (primary)
        "https://central.sonatype.com/",                                     // Maven Central (alternative)
        "https://repo.maven.apache.org/maven2/",                             // Apache Maven Repository
        "https://repository.apache.org/content/repositories/releases/",      // Apache Releases
        "https://repository.apache.org/content/repositories/snapshots/",     // Apache Snapshots
        "https://repo.spring.io/release/",                                   // Spring Framework Releases
        "https://repo.spring.io/milestone/",                                 // Spring Framework Milestones
        "https://plugins.gradle.org/m2/",                                    // Gradle Plugin Portal
        "https://repo.eclipse.org/content/repositories/releases/",           // Eclipse Releases
        "https://oss.sonatype.org/content/repositories/releases/",           // Sonatype OSS Releases
        "https://oss.sonatype.org/content/repositories/snapshots/",          // Sonatype OSS Snapshots
        "https://repo.jenkins-ci.org/releases/",                             // Jenkins CI Releases
        "https://repository.jboss.org/nexus/content/repositories/releases/", // JBoss Releases
        "https://maven.google.com/",                                         // Google Maven Repo (Android)
        "https://clojars.org/repo/",                                         // Clojars (Clojure libraries)
        "https://jitpack.io/"                                                // JitPack (GitHub/GitLab projects)
    ));

    // Pattern to match variable definitions: // @var name=value
    private static final Pattern VAR_PATTERN = Pattern.compile(
        "//\\s*@var\\s+([a-zA-Z0-9._-]+)\\s*=\\s*(.+)",
        Pattern.CASE_INSENSITIVE
    );

    // Pattern to find variable substitutions: ${varName}
    private static final Pattern VAR_SUBSTITUTION_PATTERN = Pattern.compile("\\$\\{([a-zA-Z0-9._-]+)\\}");

    // Patterns for dependency directives
    private static final Pattern DEP_PATTERN = Pattern.compile(
        "//\\s*@dep\\s+([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]+)(?:\\s+(?:sha256:([a-fA-F0-9]{64})|md5:([a-fA-F0-9]{32})))?",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern JAR_PATTERN = Pattern.compile(
        "//\\s*@jar\\s+([a-zA-Z0-9._/\\\\:-]+)",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern DIR_PATTERN = Pattern.compile(
        "//\\s*@dir\\s+([a-zA-Z0-9._/\\\\:-]+)",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern URL_PATTERN = Pattern.compile(
        "//\\s*@url\\s+(https?://\\S+)(?:\\s+(?:sha256:([a-fA-F0-9]{64})|md5:([a-fA-F0-9]{32})))?",
        Pattern.CASE_INSENSITIVE
    );

    /**
     * Cleanup resources when JVM shuts down.
     * Closes all open JAR files to prevent resource leaks.
     * This method is called automatically by the shutdown hook.
     */
    private static void cleanupResources() {
        log(VERBOSE, "Cleaning up resources...");
        for (JarFile jar : openJarFiles) {
            try {
                jar.close();
            } catch (IOException e) {
                // Log but don't throw during shutdown
                log(ERROR, "Failed to close JAR file during cleanup: " + jar.getName(), e);
            }
        }
        openJarFiles.clear();
    }

    /**
     * Entry point called by JVM when agent is loaded.
     * Processes dependency comments and adds JARs to both runtime and compilation classpath.
     *
     * @param agentArgs       Arguments passed to the agent
     * @param instrumentation JVM instrumentation interface for modifying classpath
     */
    public static void premain(String agentArgs, Instrumentation instrumentation) {
        try {
            long startTime = System.nanoTime();
            initializeConfiguration();
            log(VERBOSE, "Starting dependency resolution...");

            String command = System.getProperty("sun.java.command");
            if (command == null || command.isEmpty()) {
                log(ERROR, "Could not determine launch command.");
                return;
            }

            // Process dependencies and build classpath
            String additionalClasspath = processDependencies(command, instrumentation);

            // If we have additional dependencies, modify the system classpath
            if (!additionalClasspath.isEmpty()) {
                String currentClasspath = System.getProperty("java.class.path", "");
                String newClasspath = currentClasspath.isEmpty() ?
                        additionalClasspath : currentClasspath + File.pathSeparator + additionalClasspath;
                System.setProperty("java.class.path", newClasspath);
                log(VERBOSE, "Updated java.class.path with dependencies");
            }
            long durationMs = (System.nanoTime() - startTime) / 1_000_000;
            log(INFO, "Dependency resolution finished in " + durationMs + "ms.");
        } catch (SecurityException e) {
            log(ERROR, "Security error: " + e.getMessage());
        } catch (IOException e) {
            log(ERROR, "I/O error processing dependencies: " + e.getMessage());
        } catch (Exception e) {
            log(ERROR, "Unexpected error processing dependencies: " + e.getMessage());
        }
    }

    private static void initializeConfiguration() {
        // Initialize log level
        String logLevelStr = System.getProperty(LOG_LEVEL_PROP, System.getenv(LOG_LEVEL_ENV));
        if (logLevelStr != null && !logLevelStr.trim().isEmpty()) {
            try {
                // Allow "DEFAULT" as an alias for "INFO" for backward compatibility
                String levelToParse = "DEFAULT".equalsIgnoreCase(logLevelStr.trim()) ? "INFO" : logLevelStr.trim();
                currentLogLevel = LogLevel.valueOf(levelToParse.toUpperCase());
            } catch (IllegalArgumentException e) {
                // Invalid level provided, use default.
            }
        }

        // Initialize download timeout
        String timeoutStr = System.getProperty(DOWNLOAD_TIMEOUT_PROP, System.getenv(DOWNLOAD_TIMEOUT_ENV));
        if (timeoutStr != null) {
            try {
                downloadTimeoutSeconds = Integer.parseInt(timeoutStr);
                if (downloadTimeoutSeconds <= 0) {
                    downloadTimeoutSeconds = 30;
                }
            } catch (NumberFormatException e) {
                log(VERBOSE, "Invalid timeout value, using default: 30 seconds");
            }
        }

        // Initialize max download size
        String sizeStr = System.getProperty(MAX_DOWNLOAD_SIZE_PROP, System.getenv(MAX_DOWNLOAD_SIZE_ENV));
        if (sizeStr != null) {
            try {
                maxDownloadSize = Long.parseLong(sizeStr);
                if (maxDownloadSize <= 0) {
                    maxDownloadSize = 50 * 1024 * 1024;
                }
            } catch (NumberFormatException e) {
                log(VERBOSE, "Invalid max size value, using default: 50MB");
            }
        }

        // Initialize max retries
        String retriesStr = System.getProperty(MAX_RETRIES_PROP, System.getenv(MAX_RETRIES_ENV));
        if (retriesStr != null) {
            try {
                maxRetries = Integer.parseInt(retriesStr);
                if (maxRetries < 0) {
                    maxRetries = 3;
                }
            } catch (NumberFormatException e) {
                log(VERBOSE, "Invalid max retries value, using default: 3");
            }
        }

        // Initialize parallel downloads
        String parallelStr = System.getProperty(PARALLEL_DOWNLOADS_PROP, System.getenv(PARALLEL_DOWNLOADS_ENV));
        if (parallelStr != null) {
            try {
                parallelDownloads = Integer.parseInt(parallelStr);
                if (parallelDownloads <= 0) {
                    parallelDownloads = 4; // Reset to default if invalid
                }
            } catch (NumberFormatException e) {
                log(VERBOSE, "Invalid parallel downloads value, using default: 4");
            }
        }

        // Initialize cache directory
        String cacheDirStr = System.getProperty(CACHE_DIR_PROP, System.getenv(CACHE_DIR_ENV));
        if (cacheDirStr != null && !cacheDirStr.trim().isEmpty()) {
            cacheDir = Paths.get(cacheDirStr.trim());
            log(VERBOSE, "Using custom cache directory: " + cacheDir);
        }

        // Initialize trusted repositories
        trustedRepos = new HashSet<>(TRUSTED_REPOS);
        String additionalRepos = System.getProperty(TRUSTED_REPOS_PROP, System.getenv(TRUSTED_REPOS_ENV));

        if (additionalRepos != null && !additionalRepos.trim().isEmpty()) {
            String[] repos = additionalRepos.split("[,;]");
            for (String repo : repos) {
                repo = repo.trim();
                if (!repo.isEmpty() && (repo.startsWith("http://") || repo.startsWith("https://"))) {
                    if (!repo.endsWith("/")) {
                        repo += "/";
                    }
                    trustedRepos.add(repo);
                    log(VERBOSE, "Added trusted repository: " + repo);
                }
            }
        }
    }

    /**
     * Performs variable substitution on a line. Replaces `${var}` with its defined value.
     */
    private static String substituteVariables(String line, Map<String, String> variables) {
        if (variables.isEmpty() || !line.contains("${")) {
            return line; // Quick exit if no variables are defined or no placeholders exist
        }

        Matcher matcher = VAR_SUBSTITUTION_PATTERN.matcher(line);
        StringBuffer stringBuffer = new StringBuffer();

        while (matcher.find()) {
            String varName = matcher.group(1);
            String varValue = variables.get(varName);
            if (varValue != null) {
                // Use quoteReplacement to handle special characters in the value
                matcher.appendReplacement(stringBuffer, Matcher.quoteReplacement(varValue));
            } else {
                log(ERROR, "Variable '" + varName + "' not defined, but used in: " + line);
                // Leave the placeholder as-is if not found, to make the error obvious
                matcher.appendReplacement(stringBuffer, Matcher.quoteReplacement(matcher.group(0)));
            }
        }
        matcher.appendTail(stringBuffer);
        return stringBuffer.toString();
    }

    /**
     * Processes all dependency comments from the source file.
     * Uses a two-pass model to handle variables.
     * Returns a classpath string containing all resolved dependency paths.
     *
     * @param command         The java command used to launch the application
     * @param instrumentation JVM instrumentation for runtime classpath modification
     * @return Semicolon/colon-separated classpath string of all dependencies
     * @throws IOException If source file cannot be read
     */
    private static String processDependencies(String command, Instrumentation instrumentation) throws IOException {
        Path sourcePath = findSourcePath(command);
        if (!Files.exists(sourcePath)) {
            log(ERROR, "Source file not found: " + sourcePath);
            return "";
        }

        log(INFO, "Processing dependencies from: " + sourcePath);

        List<String> allLines = Files.readAllLines(sourcePath);
        Map<String, String> variables = new HashMap<>();

        // Pass 1: Collect all variable definitions, resolving them as we go.
        log(VERBOSE, "Pass 1: Scanning for variable definitions...");
        for (String line : allLines) {
            Matcher varMatcher = VAR_PATTERN.matcher(line.trim());
            if (varMatcher.find()) {
                String name = varMatcher.group(1).trim();
                String value = varMatcher.group(2).trim();
                // Substitute existing variables in the value before storing it.
                String substitutedValue = substituteVariables(value, variables);
                variables.put(name, substitutedValue);
                log(VERBOSE, "Defined variable: " + name + " = " + substitutedValue);
            }
        }

        // Pass 2: Process directives with variable substitution
        log(VERBOSE, "Pass 2: Processing dependency directives...");
        if (parallelDownloads <= 1) {
            log(VERBOSE, "Using sequential processing.");
            return allLines.stream()
                    .map(String::trim)
                    .filter(line -> !VAR_PATTERN.matcher(line).matches())
                    .map(line -> substituteVariables(line, variables))
                    .map(substitutedLine -> processDependencyLine(substitutedLine, instrumentation))
                    .filter(jarPath -> jarPath != null && !jarPath.isEmpty())
                    .collect(Collectors.joining(File.pathSeparator));
        }

        ForkJoinPool customPool = new ForkJoinPool(parallelDownloads);
        try {
            log(VERBOSE, "Using parallel processing with " + parallelDownloads + " threads.");
            return customPool.submit(() ->
                    allLines.parallelStream()
                            .map(String::trim)
                            .filter(line -> !VAR_PATTERN.matcher(line).matches())
                            .map(line -> substituteVariables(line, variables))
                            .map(substitutedLine -> processDependencyLine(substitutedLine, instrumentation))
                            .filter(jarPath -> jarPath != null && !jarPath.isEmpty())
                            .collect(Collectors.joining(File.pathSeparator))
            ).get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Parallel dependency processing was interrupted", e);
        } catch (Exception e) {
            throw new IOException("Failed to process dependencies in parallel", e);
        } finally {
            customPool.shutdown();
        }
    }

    /**
     * Processes a single line, variable-substituted from the source file, checking for dependency comments.
     * Supports @dep, @jar, @dir, and @url directives.
     * Implements graceful degradation when dependencies fail.
     *
     * @param line            Line of source code to process
     * @param instrumentation JVM instrumentation for runtime classpath modification
     * @return Absolute path to the JAR file(s) added, or null if no dependency found or failed
     */
    private static String processDependencyLine(String line, Instrumentation instrumentation) {
        // This method now receives a line that has already had variables substituted.
        line = line.trim();

        // Check for Maven dependency: // @dep groupId:artifactId:version [sha256:xxx|md5:xxx]
        Matcher depMatcher = DEP_PATTERN.matcher(line);
        if (depMatcher.find()) {
            String groupId = depMatcher.group(1);
            String artifactId = depMatcher.group(2);
            String version = depMatcher.group(3);
            String sha256Checksum = depMatcher.group(4);
            String md5Checksum = depMatcher.group(5);

            log(VERBOSE, "Found dependency: " + groupId + ":" + artifactId + ":" + version);

            try {
                return downloadAndAddDependency(groupId, artifactId, version, sha256Checksum, md5Checksum, instrumentation);
            } catch (SecurityException e) {
                log(ERROR, "Security error for dependency " + groupId + ":" + artifactId + ":" + version + ": " + e.getMessage());
                return null;
            } catch (IOException e) {
                log(ERROR, "I/O error for dependency " + groupId + ":" + artifactId + ":" + version + ": " + e.getMessage());
                return null;
            } catch (Exception e) {
                log(ERROR, "Failed to resolve dependency " + groupId + ":" + artifactId + ":" + version, e);
                return null;
            }
        }

        // Check for local JAR file: // @jar path/to/file.jar
        Matcher jarMatcher = JAR_PATTERN.matcher(line);
        if (jarMatcher.find()) {
            String jarPath = jarMatcher.group(1).trim();
            log(VERBOSE, "Found JAR: " + jarPath);

            try {
                return addLocalJar(jarPath, instrumentation);
            } catch (SecurityException e) {
                log(ERROR, "Security error for JAR " + jarPath + ": " + e.getMessage());
                return null;
            } catch (IOException e) {
                log(ERROR, "I/O error for JAR " + jarPath + ": " + e.getMessage());
                return null;
            } catch (Exception e) {
                log(ERROR, "Failed to add local JAR " + jarPath, e);
                return null;
            }
        }

        // Check for directory of JARs: // @dir path/to/directory/
        Matcher dirMatcher = DIR_PATTERN.matcher(line);
        if (dirMatcher.find()) {
            String dirPath = dirMatcher.group(1).trim();
            log(VERBOSE, "Found directory: " + dirPath);

            try {
                return addJarsFromDirectory(dirPath, instrumentation);
            } catch (SecurityException e) {
                log(ERROR, "Security error for directory " + dirPath + ": " + e.getMessage());
                return null;
            } catch (IOException e) {
                log(ERROR, "I/O error for directory " + dirPath + ": " + e.getMessage());
                return null;
            } catch (Exception e) {
                log(ERROR, "Unexpected error for directory " + dirPath + ": " + e.getMessage());
                return null;
            }
        }

        // Check for URL download: // @url https://example.com/lib.jar [sha256:xxx|md5:xxx]
        Matcher urlMatcher = URL_PATTERN.matcher(line);
        if (urlMatcher.find()) {
            String url = urlMatcher.group(1);
            String sha256Checksum = urlMatcher.group(2);
            String md5Checksum = urlMatcher.group(3);
            log(VERBOSE, "Found URL: " + url);

            try {
                return downloadAndAddFromUrl(url, sha256Checksum, md5Checksum, instrumentation);
            } catch (SecurityException e) {
                log(ERROR, "Security error for URL " + url + ": " + e.getMessage());
                return null;
            } catch (IOException e) {
                log(ERROR, "I/O error for URL " + url + ": " + e.getMessage());
                return null;
            } catch (Exception e) {
                log(ERROR, "Unexpected error for URL " + url + ": " + e.getMessage());
                return null;
            }
        }

        // If we fall through, no valid directive was found.
        // Check if the line appears to be a malformed directive and log an error.
        if (line.matches("//\\s*@(dep|jar|dir|url).*")) {
            // This line starts like one of our directives but failed to parse fully.
            String hint = "";
            if (line.contains("@dep")) {
                hint = " Hint: Check format 'groupId:artifactId:version'.";
            }
            if (line.contains("${")) {
                hint += " Hint: Check for an unclosed or undefined variable, e.g., missing '}'.";
            } else if (line.contains("$")) {
                hint += " Hint: Variables must use the ${name} format.";
            }
            log(ERROR, "Malformed or incomplete dependency directive." + hint + " Offending line: " + line);
        }

        // No dependency directive found in this line
        return null;
    }

    /**
     * Constructs the path to a JAR in the local Maven (.m2) repository.
     * @param groupId Maven group ID
     * @param artifactId Maven artifact ID
     * @param version Maven version
     * @return The potential path to the JAR file, or null if user home is not found.
     */
    private static Path resolveMavenPath(String groupId, String artifactId, String version) {
        String userHome = System.getProperty("user.home");
        if (userHome == null) {
            log(VERBOSE, "User home directory not found, skipping .m2 repository check.");
            return null;
        }

        Path m2RepoPath = Paths.get(userHome, ".m2", "repository");
        String groupPath = groupId.replace('.', File.separatorChar);
        String jarName = artifactId + "-" + version + ".jar";

        // Construct the full path using resolve for cross-platform safety
        return m2RepoPath.resolve(groupPath)
                         .resolve(artifactId)
                         .resolve(version)
                         .resolve(jarName);
    }

    /**
     * Downloads a Maven artifact from Maven Central and adds it to the classpath.
     * Uses local cache to avoid re-downloading existing artifacts.
     * <p>
     * This method implements the complete lifecycle for Maven dependency resolution:
     * </p>
     * <ol>
     *   <li>Validates Maven coordinates to prevent injection attacks</li>
     *   <li>Checks local cache for existing artifact</li>
     *   <li>Downloads from Maven Central if not cached</li>
     *   <li>Verifies integrity using provided checksums</li>
     *   <li>Validates the JAR file structure</li>
     *   <li>Adds to runtime classpath via instrumentation</li>
     * </ol>
     *
     * @param groupId         Maven group ID (e.g., "org.apache.commons")
     * @param artifactId      Maven artifact ID (e.g., "commons-lang3")
     * @param version         Version string (e.g., "3.12.0")
     * @param sha256Checksum  Optional SHA-256 checksum for verification (64 hex chars)
     * @param md5Checksum     Optional MD5 checksum for verification (32 hex chars, alternative to SHA-256)
     * @param instrumentation JVM instrumentation for runtime classpath modification
     * @return Absolute path to the downloaded JAR file
     * @throws Exception If download fails, validation fails, or security checks fail
     */
    private static String downloadAndAddDependency(String groupId, String artifactId, String version,
                                                   String sha256Checksum, String md5Checksum, Instrumentation instrumentation) throws Exception {

        // Validate inputs to prevent injection attacks
        validateMavenCoordinate(groupId, artifactId, version);

        // Check local Maven repository first
        Path m2JarPath = resolveMavenPath(groupId, artifactId, version);
        if (m2JarPath != null && Files.exists(m2JarPath)) {
            log(INFO, "Found dependency in local Maven repository: " + m2JarPath.getFileName());
            try {
                if (verifyAnyChecksum(m2JarPath, sha256Checksum, md5Checksum)) {
                    validateJarFile(m2JarPath);
                    addJarToClasspath(m2JarPath, instrumentation);
                    return m2JarPath.toAbsolutePath().toString();
                } else {
                    log(INFO, "Local Maven repository file checksum mismatch for " + m2JarPath.getFileName() + ". Will attempt download.");
                }
            } catch (IOException e) {
                log(INFO, "Local Maven repository file is invalid or corrupted (" + m2JarPath.getFileName() + "): " + e.getMessage() + ". Will attempt download.");
            }
        }

        String filename = artifactId + "-" + version + ".jar";
        Path cacheFile = getCacheDir().resolve(filename);

        // Check if already cached with proper TOCTOU handling
        if (Files.exists(cacheFile)) {
            log(INFO, "Using cached dependency: " + filename);
            try {
                if (verifyAnyChecksum(cacheFile, sha256Checksum, md5Checksum)) {
                    addJarToClasspath(cacheFile, instrumentation);
                    return cacheFile.toAbsolutePath().toString();
                } else {
                    log(ERROR, "Cached file checksum mismatch for " + filename);
                    Files.deleteIfExists(cacheFile); // Use deleteIfExists to handle race conditions
                }
            } catch (IOException e) {
                log(VERBOSE, "Cache file disappeared or corrupted, re-downloading: " + filename);
            }
        }

        // Download from Maven Central (most trusted)
        String downloadUrl = buildMavenCentralUrl(groupId, artifactId, version);
        log(INFO, "Downloading : " + downloadUrl);

        downloadFile(downloadUrl, cacheFile);

        // Verify checksum if provided
        if (!verifyAnyChecksum(cacheFile, sha256Checksum, md5Checksum)) {
            Files.deleteIfExists(cacheFile);
            throw new SecurityException("Checksum verification failed for " + filename);
        }

        validateJarFile(cacheFile);

        addJarToClasspath(cacheFile, instrumentation);
        log(INFO, "Successfully added dependency: " + filename);

        return cacheFile.toAbsolutePath().toString();
    }

    /**
     * Adds a local JAR file to the classpath.
     * Resolves relative paths against the current working directory.
     * <p>
     * This method provides secure access to local JAR files with the following protections:
     * </p>
     * <ul>
     *   <li>Path traversal protection for relative paths</li>
     *   <li>Validation of absolute paths against allowed directories</li>
     *   <li>JAR file structure validation</li>
     *   <li>Existence and accessibility checks</li>
     * </ul>
     *
     * @param jarPath         Path to the JAR file (absolute or relative)
     * @param instrumentation JVM instrumentation for runtime classpath modification
     * @return Absolute path to the JAR file
     * @throws IOException       If file doesn't exist, isn't accessible, or isn't a valid JAR
     * @throws SecurityException If path is outside allowed directories (security protection)
     */
    private static String addLocalJar(String jarPath, Instrumentation instrumentation) throws IOException, SecurityException {
        Path projectRoot = Paths.get(System.getProperty("user.dir")).normalize().toAbsolutePath();
        Path jarFile = Paths.get(jarPath).normalize().toAbsolutePath();

        // Security check: prevent path traversal attacks for relative paths
        // For absolute paths, we still need to validate they're safe
        if (!jarFile.startsWith(projectRoot)) {
            // Allow absolute paths to common library directories
            boolean isAllowedAbsolutePath = isAllowedAbsolutePath(jarFile);
            if (!isAllowedAbsolutePath) {
                throw new SecurityException("Path outside allowed directories: " + jarPath);
            }
        }

        if (!Files.exists(jarFile)) {
            throw new IOException("JAR file not found: " + jarFile);
        }

        if (!Files.isRegularFile(jarFile)) {
            throw new IOException("Path is not a file: " + jarFile);
        }

        // Validate it's a JAR file
        validateJarFile(jarFile);

        addJarToClasspath(jarFile, instrumentation);
        log(INFO, "Successfully added local JAR: " + jarFile.getFileName());

        return jarFile.toAbsolutePath().toString();
    }

    /**
     * Checks if an absolute path is in an allowed directory for security.
     * <p>
     * This method implements a whitelist of safe directories where JAR files
     * can be loaded from. This prevents malicious code from loading JARs
     * from arbitrary system locations.
     * </p>
     *
     * @param path The absolute path to check
     * @return true if the path is in an allowed directory
     */
    private static boolean isAllowedAbsolutePath(Path path) {
        String pathStr = path.toString();
        // Allow common Java library directories
        return pathStr.startsWith("/usr/share/java/") ||
                pathStr.startsWith("/opt/java/") ||
                pathStr.startsWith("/Library/Java/") ||
                pathStr.startsWith(System.getProperty("java.home")) ||
                pathStr.startsWith(System.getProperty("user.home"));
    }

    /**
     * Adds all JAR files from a directory to the classpath.
     * Scans the directory for files ending in .jar and adds each one.
     * <p>
     * This method provides bulk loading of JAR files from a directory with:
     * </p>
     * <ul>
     *   <li>Security validation of the directory path</li>
     *   <li>Recursive scanning for .jar files</li>
     *   <li>Individual validation of each JAR file</li>
     *   <li>Graceful handling of invalid files (logged but not fatal)</li>
     * </ul>
     *
     * @param dirPath         Path to directory containing JAR files
     * @param instrumentation JVM instrumentation for runtime classpath modification
     * @return Classpath string containing all JAR files from the directory (platform-specific separator)
     * @throws IOException       If directory doesn't exist, can't be read, or access fails
     * @throws SecurityException If path is outside allowed directories (security protection)
     */
    private static String addJarsFromDirectory(String dirPath, Instrumentation instrumentation) throws IOException, SecurityException {
        Path projectRoot = Paths.get(System.getProperty("user.dir")).normalize().toAbsolutePath();
        Path directory = Paths.get(dirPath).normalize().toAbsolutePath();

        // Security check: prevent path traversal attacks for relative paths
        if (!directory.startsWith(projectRoot)) {
            boolean isAllowedAbsolutePath = isAllowedAbsolutePath(directory);
            if (!isAllowedAbsolutePath) {
                throw new SecurityException("Directory path outside allowed directories: " + dirPath);
            }
        }

        if (!Files.exists(directory)) {
            throw new IOException("Directory not found: " + directory);
        }

        if (!Files.isDirectory(directory)) {
            throw new IOException("Path is not a directory: " + directory);
        }

        log(VERBOSE, "Scanning directory for JARs: " + directory);

        File[] jarFiles = directory.toFile().listFiles((dir, name) -> name.toLowerCase().endsWith(".jar"));
        if (jarFiles == null || jarFiles.length == 0) {
            log(VERBOSE, "No JAR files found in directory: " + directory);
            return "";
        }

        StringBuilder classpathBuilder = new StringBuilder();

        for (File jarFile : jarFiles) {
            try {
                validateJarFile(jarFile.toPath());
                addJarToClasspath(jarFile.toPath(), instrumentation);
                log(INFO, "Added JAR from directory: " + jarFile.getName());

                if (classpathBuilder.length() > 0) {
                    classpathBuilder.append(File.pathSeparator);
                }
                classpathBuilder.append(jarFile.getAbsolutePath());
            } catch (Exception e) {
                log(ERROR, "Failed to add JAR: " + jarFile.getName() + " - " + e.getMessage());
                log(VERBOSE, "JAR addition failure details for " + jarFile.getName(), e);
            }
        }

        return classpathBuilder.toString();
    }

    /**
     * Downloads a JAR file from a URL and adds it to the classpath.
     * Only allows downloads from trusted repositories for security.
     * <p>
     * This method implements secure URL-based dependency resolution with:
     * </p>
     * <ul>
     *   <li>Repository trust validation against whitelist</li>
     *   <li>Local cache management with integrity checking</li>
     *   <li>Secure download with timeouts and size limits</li>
     *   <li>Optional checksum verification for integrity</li>
     *   <li>JAR file structure validation</li>
     * </ul>
     *
     * @param urlString       URL to download the JAR from (must be from trusted repository)
     * @param sha256Checksum  Optional SHA-256 checksum for verification (64 hex characters)
     * @param md5Checksum     Optional MD5 checksum for verification (32 hex characters, alternative to SHA-256)
     * @param instrumentation JVM instrumentation for runtime classpath modification
     * @return Absolute path to the downloaded JAR file
     * @throws Exception If download fails, URL is untrusted, validation fails, or security checks fail
     */
    private static String downloadAndAddFromUrl(String urlString, String sha256Checksum, String md5Checksum, Instrumentation instrumentation) throws Exception {
        URL url = new URL(urlString);

        // Security check - only allow trusted repositories
        if (!isTrustedRepository(urlString)) {
            throw new SecurityException("Untrusted repository: " + url.getHost() + ". Only trusted Maven repositories are allowed.");
        }

        // Extract filename from URL
        String urlPath = url.getPath();
        String filename = urlPath.substring(urlPath.lastIndexOf('/') + 1);
        if (!filename.endsWith(".jar")) {
            filename = "downloaded-" + System.currentTimeMillis() + ".jar";
        }

        Path cacheFile = getCacheDir().resolve(filename);

        // Check if already cached with proper "Time-of-Check to Time-of-Use" handling
        if (Files.exists(cacheFile)) {
            log(INFO, "Using cached URL dependency: " + filename);
            try {
                if (!verifyAnyChecksum(cacheFile, sha256Checksum, md5Checksum)) {
                    log(ERROR, "Cached file checksum mismatch for " + filename);
                    Files.deleteIfExists(cacheFile);
                } else {
                    addJarToClasspath(cacheFile, instrumentation);
                    return cacheFile.toAbsolutePath().toString();
                }
            } catch (IOException e) {
                log(VERBOSE, "Cache file disappeared or corrupted, re-downloading: " + filename);
            }
        }

        log(INFO, "Downloading from URL: " + urlString);
        downloadFile(urlString, cacheFile);

        // Verify checksum if provided
        if (!verifyAnyChecksum(cacheFile, sha256Checksum, md5Checksum)) {
            Files.deleteIfExists(cacheFile);
            throw new SecurityException("Checksum verification failed for " + filename);
        }

        // Validate JAR file
        validateJarFile(cacheFile);

        addJarToClasspath(cacheFile, instrumentation);
        log(INFO, "Successfully downloaded and added: " + filename);

        return cacheFile.toAbsolutePath().toString();
    }
    
    /**
     * Checks if a URL is from a trusted repository.
     * <p>
     * This method implements repository trust validation by checking if the URL
     * starts with any of the configured trusted repository URLs. This prevents
     * downloading dependencies from untrusted or potentially malicious sources.
     * </p>
     *
     * @param urlString The URL to validate
     * @return true if URL is from a trusted repository, false otherwise
     */
    private static boolean isTrustedRepository(String urlString) {
        try {
            new URL(urlString); // basic validation
            for (String repo : trustedRepos) {
                if (urlString.startsWith(repo)) {
                    return true;
                }
            }
            return false;
        } catch (MalformedURLException e) {
            return false;
        }
    }

    /**
     * Validates Maven coordinates to prevent injection attacks.
     * Ensures groupId, artifactId, and version contain only safe characters.
     * <p>
     * This method implements input validation to prevent various security issues:
     * </p>
     * <ul>
     *   <li>Path injection attacks in Maven coordinates</li>
     *   <li>URL manipulation through malicious coordinates</li>
     *   <li>Command injection via coordinate values</li>
     * </ul>
     * <p>
     * Allowed characters: letters, numbers, dots, underscores, and hyphens only.
     * </p>
     *
     * @param groupId    Maven group ID (e.g., "org.apache.commons")
     * @param artifactId Maven artifact ID (e.g., "commons-lang3")
     * @param version    Version string (e.g., "3.12.0")
     * @throws IllegalArgumentException If any coordinate contains invalid characters
     */
    private static void validateMavenCoordinate(String groupId, String artifactId, String version) {
        if (!groupId.matches("[a-zA-Z0-9._-]+") ||
                !artifactId.matches("[a-zA-Z0-9._-]+") ||
                !version.matches("[a-zA-Z0-9._-]+")) {
            throw new IllegalArgumentException("Invalid Maven coordinate format");
        }
    }

    /**
     * Builds the Maven Central URL for a given artifact.
     * Converts group ID dots to slashes and constructs the standard Maven path.
     * <p>
     * Maven repository URL structure follows the pattern:
     * {@code https://repo1.maven.org/maven2/[groupPath]/[artifactId]/[version]/[artifactId]-[version].jar}
     * where groupPath is the groupId with dots replaced by forward slashes.
     * </p>
     *
     * @param groupId    Maven group ID (dots will be converted to slashes)
     * @param artifactId Maven artifact ID
     * @param version    Version string
     * @return Complete URL to the JAR file on Maven Central
     */
    private static String buildMavenCentralUrl(String groupId, String artifactId, String version) {
        String groupPath = groupId.replace('.', '/');
        return String.format("https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.jar",
                groupPath, artifactId, version, artifactId, version);
    }

    /**
     * Validates that a file is a proper JAR file by attempting to open it.
     * Throws an exception if the file is corrupted or not a valid JAR.
     * <p>
     * This method performs basic JAR file validation by trying to open it
     * as a JarFile. This catches common issues like:
     * </p>
     * <ul>
     *   <li>Corrupted ZIP/JAR structure</li>
     *   <li>Incomplete downloads</li>
     *   <li>Non-JAR files with .jar extension</li>
     *   <li>Permission or access issues</li>
     * </ul>
     *
     * @param jarPath Path to the JAR file to validate
     * @throws IOException If the file cannot be opened as a JAR
     */
    private static void validateJarFile(Path jarPath) throws IOException {
        // Basic validation - try to open as JAR
        try (JarFile jarFile = new JarFile(jarPath.toFile())) {
            // JAR file is valid if we can open it
            log(VERBOSE, "JAR validation successful: " + jarPath.getFileName());
        }
    }

    /**
     * Downloads a file from a URL to a local destination with retry logic.
     * Includes security checks, timeouts, and size limits.
     * <p>
     * This method implements robust file downloading with:
     * </p>
     * <ul>
     *   <li>Repository trust validation</li>
     *   <li>Connection and read timeouts</li>
     *   <li>File size limits to prevent DoS attacks</li>
     *   <li>Exponential backoff retry logic</li>
     *   <li>SSL/TLS certificate validation</li>
     *   <li>Proper user agent and accept headers</li>
     * </ul>
     *
     * @param urlString   URL to download from (must be from trusted repository)
     * @param destination Local path to save the file
     * @throws IOException       If download fails after all retries
     * @throws SecurityException If URL is from an untrusted repository
     */
    private static void downloadFile(String urlString, Path destination) throws IOException, SecurityException {
        URL url = new URL(urlString);

        // Ensure we're downloading from trusted repository
        if (!isTrustedRepository(urlString)) {
            throw new SecurityException("Untrusted repository: " + url.getHost());
        }

        IOException lastException = null;

        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                log(VERBOSE, "Download attempt " + attempt + "/" + maxRetries + ": " + urlString);

                URLConnection connection = url.openConnection();
                connection.setConnectTimeout(downloadTimeoutSeconds * 1000);
                connection.setReadTimeout(downloadTimeoutSeconds * 1000);
                connection.setRequestProperty("User-Agent", "JarGet/" + JARGET_VERSION);
                connection.setRequestProperty("Accept", "application/java-archive, application/octet-stream, */*");

                // Enable certificate validation for HTTPS
                if (connection instanceof HttpsURLConnection) {
                    HttpsURLConnection httpsConnection = (HttpsURLConnection) connection;
                    // Use default SSL context which includes certificate validation
                    httpsConnection.setSSLSocketFactory(SSLContext.getDefault().getSocketFactory());
                }

                try (InputStream in = connection.getInputStream()) {
                    long bytesDownloaded = Files.copy(in, destination, StandardCopyOption.REPLACE_EXISTING);

                    if (bytesDownloaded > maxDownloadSize) {
                        Files.deleteIfExists(destination);
                        throw new IOException("Downloaded file exceeds maximum size limit: " + maxDownloadSize + " bytes");
                    }

                    log(VERBOSE, "Successfully downloaded " + bytesDownloaded + " bytes");
                    return; // Success
                }

            } catch (IOException e) {
                lastException = e;
                log(VERBOSE, "Download attempt " + attempt + " failed: " + e.getMessage());

                if (attempt < maxRetries) {
                    try {
                        // Exponential backoff: 1s, 2s, 4s, etc.
                        long delayMs = 1000L * (1L << (attempt - 1));
                        log(VERBOSE, "Retrying in " + delayMs + "ms...");
                        Thread.sleep(delayMs);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Download interrupted", ie);
                    }
                }
            } catch (Exception e) {
                throw new IOException("Download failed due to unexpected error: " + e.getMessage(), e);
            }
        }

        // All retries failed
        throw new IOException("Download failed after " + maxRetries + " attempts. Last error: " +
                (lastException != null ? lastException.getMessage() : "Unknown error"));
    }

    /**
     * Verifies either SHA-256 or MD5 checksum of a file, whichever is provided.
     * If both are provided, verifies both. If neither is provided, returns true.
     * Used to ensure downloaded files haven't been tampered with.
     * <p>
     * This method implements flexible integrity verification with support for
     * multiple hash algorithms. It uses streaming I/O to handle large files
     * efficiently without loading them entirely into memory.
     * </p>
     *
     * @param file           Path to the file to verify
     * @param sha256Checksum Expected SHA-256 checksum in hexadecimal (optional, 64 characters)
     * @param md5Checksum    Expected MD5 checksum in hexadecimal (optional, 32 characters)
     * @return true if no checksums provided or if all provided checksums match, false if any mismatch
     */
    private static boolean verifyAnyChecksum(Path file, String sha256Checksum, String md5Checksum) {
        // If no checksums provided, consider it valid
        if (sha256Checksum == null && md5Checksum == null) {
            return true;
        }

        boolean sha256Valid = true;
        boolean md5Valid = true;

        // Verify SHA-256 if provided
        if (sha256Checksum != null) {
            sha256Valid = verifyChecksum(file, sha256Checksum, "SHA-256");
            if (sha256Valid) {
                log(VERBOSE, "SHA-256 checksum verification passed");
            }
        }

        // Verify MD5 if provided
        if (md5Checksum != null) {
            md5Valid = verifyChecksum(file, md5Checksum, "MD5");
            if (md5Valid) {
                log(VERBOSE, "MD5 checksum verification passed");
            }
        }

        // Return true if at least one checksum is valid (when provided)
        return sha256Valid && md5Valid;
    }

    /**
     * Verifies the checksum of a file using the specified algorithm.
     * Uses streaming to handle large files without loading them entirely into memory.
     * <p>
     * This method implements efficient hash verification by:
     * </p>
     * <ul>
     *   <li>Using streaming I/O with buffered reads</li>
     *   <li>Supporting multiple hash algorithms (SHA-256, MD5, etc.)</li>
     *   <li>Performing case-insensitive checksum comparison</li>
     *   <li>Proper exception handling and logging</li>
     * </ul>
     *
     * @param file             Path to the file to verify
     * @param expectedChecksum Expected checksum in hexadecimal (case-insensitive)
     * @param algorithm        Hash algorithm name ("SHA-256", "MD5", etc.)
     * @return true if checksum matches exactly, false if mismatch or error occurs
     */
    private static boolean verifyChecksum(Path file, String expectedChecksum, String algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);

            // Use streaming to avoid loading large files into memory
            try (InputStream fis = Files.newInputStream(file)) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    digest.update(buffer, 0, bytesRead);
                }
            }

            byte[] hashBytes = digest.digest();
            StringBuilder stringBuilder = new StringBuilder();
            for (byte b : hashBytes) {
                stringBuilder.append(String.format("%02x", b));
            }

            return stringBuilder.toString().equalsIgnoreCase(expectedChecksum);
        } catch (Exception e) {
            log(ERROR, algorithm + " checksum verification failed: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Determines the source file path from the Java command line.
     * Looks for .java files in command args, or infers from class name.
     * <p>
     * This method implements intelligent source file detection using multiple strategies:
     * </p>
     * <ol>
     *   <li>Direct .java file reference in command arguments</li>
     *   <li>Qualified class name resolution to Maven-style paths</li>
     *   <li>Simple class name resolution in current directory</li>
     *   <li>Fallback to standard Maven directory structure</li>
     * </ol>
     *
     * @param command The complete java command that launched the application
     * @return Path to the source file that should contain dependency comments
     */
    private static Path findSourcePath(String command) {
        String[] commandParts = command.split("\\s+");
        String projectRoot = System.getProperty("user.dir");

        // Look for .java file in command
        for (String part : commandParts) {
            if (part.endsWith(".java")) {
                return Paths.get(projectRoot, part);
            }
        }

        // Infer from class name - handle both simple and qualified class names
        String className = commandParts[commandParts.length - 1];
        if (className.contains(".")) {
            // Qualified class name
            String sourcePath = className.replace('.', '/') + ".java";
            Path srcPath = Paths.get(projectRoot, "src", "main", "java", sourcePath);
            if (Files.exists(srcPath)) {
                return srcPath;
            }
            // Try current directory
            return Paths.get(projectRoot, sourcePath);
        } else {
            // Simple class name - try current directory first
            Path currentDir = Paths.get(projectRoot, className + ".java");
            if (Files.exists(currentDir)) {
                return currentDir;
            }
            // Try standard Maven structure
            return Paths.get(projectRoot, "src", "main", "java", className + ".java");
        }
    }

    /**
     * Gets or creates the cache directory for downloaded dependencies.
     * Uses ~/.jarget/cache following the pattern of other dependency tools.
     * <p>
     * This method implements cache directory management with:
     * </p>
     * <ul>
     *   <li>Configurable cache location via system properties or environment variables</li>
     *   <li>Default location following Unix conventions (~/.jarget/cache)</li>
     *   <li>Automatic directory creation with proper permissions</li>
     *   <li>Thread-safe initialization</li>
     * </ul>
     *
     * @return Path to the cache directory (created if it doesn't exist)
     * @throws IOException If directory cannot be created or accessed
     */
    private static synchronized Path getCacheDir() throws IOException {
        if (cacheDir == null) {
            // Use user's cache directory, similar to how uv works
            String userHome = System.getProperty("user.home");
            cacheDir = Paths.get(userHome, ".jarget", "cache");
        }

        if (!Files.exists(cacheDir)) {
            Files.createDirectories(cacheDir);
            log(VERBOSE, "Created cache directory: " + cacheDir);
        } else {
            log(VERBOSE, "Using cache directory: " + cacheDir);
        }
        return cacheDir;
    }

    /**
     * Adds a JAR file to the JVM's classpath at runtime.
     * Uses the Instrumentation API to modify the system classloader.
     * Keeps a reference to prevent the JarFile from being garbage collected.
     * <p>
     * This method implements runtime classpath modification using the Java
     * Instrumentation API. It maintains references to JAR files to prevent
     * premature garbage collection which would make classes unavailable.
     * </p>
     *
     * @param jarPath         Path to the JAR file to add
     * @param instrumentation JVM instrumentation interface
     * @throws IOException If the JAR file cannot be accessed or opened
     */
    private static void addJarToClasspath(Path jarPath, Instrumentation instrumentation) throws IOException {
        JarFile jarFile = new JarFile(jarPath.toFile());
        try {
            instrumentation.appendToSystemClassLoaderSearch(jarFile);
            // Keep reference to prevent GC from closing the JarFile
            openJarFiles.add(jarFile);
            log(VERBOSE, "Added to classpath: " + jarPath.getFileName());
        } catch (Exception e) {
            // If instrumentation fails, close the JarFile to prevent resource leak
            try {
                jarFile.close();
            } catch (IOException closeException) {
                e.addSuppressed(closeException);
            }
            throw e;
        }
    }

    /**
     * Main method to display usage information and cache statistics.
     * Run with: java -jar agent.jar
     * <p>
     * This method provides a comprehensive help system and diagnostic information
     * when the agent JAR is executed directly. It displays:
     * </p>
     * <ul>
     *   <li>Usage instructions and command-line examples</li>
     *   <li>Complete list of supported dependency directives</li>
     *   <li>Configuration options with system property and environment variable names</li>
     *   <li>Current configuration values</li>
     *   <li>Cache directory location and statistics</li>
     *   <li>List of trusted repositories</li>
     *   <li>Practical usage examples</li>
     * </ul>
     *
     * @param args Command line arguments (currently unused)
     */
    public static void main(String[] args) {
        System.out.println("Jarget - Dependency Management for Java");
        System.out.println("=======================================");

        System.out.println("\nUSAGE:");
        System.out.println("  java -javaagent:agent.jar [options] YourScript.java");

        System.out.println("\nDEPENDENCY DIRECTIVES:");
        System.out.println("  // @dep groupId:artifactId:version [sha256:hash|md5:hash]");
        System.out.println("  // @url https://repo.com/lib.jar [sha256:hash|md5:hash]");
        System.out.println("  // @jar path/to/local.jar");
        System.out.println("  // @dir path/to/jar-directory/");

        System.out.println("\nCONFIGURATION (System Properties or Environment Variables):");
        System.out.println("  Log Level:");
        System.out.println("    -D" + LOG_LEVEL_PROP + "=SILENT|ERROR|INFO|VERBOSE");
        System.out.println("    " + LOG_LEVEL_ENV + "=SILENT|ERROR|INFO|VERBOSE");

        System.out.println("\n  Trusted Repositories (comma/semicolon separated):");
        System.out.println("    -D" + TRUSTED_REPOS_PROP + "=https://jitpack.io/,https://my-nexus.com/");
        System.out.println("    " + TRUSTED_REPOS_ENV + "=https://jitpack.io/;https://my-nexus.com/");

        System.out.println("\n  Download Settings:");
        System.out.println("    -D" + DOWNLOAD_TIMEOUT_PROP + "=60");
        System.out.println("    " + DOWNLOAD_TIMEOUT_ENV + "=60");
        System.out.println("    -D" + MAX_DOWNLOAD_SIZE_PROP + "=104857600  # 100MB in bytes");
        System.out.println("    " + MAX_DOWNLOAD_SIZE_ENV + "=104857600");
        System.out.println("    -D" + MAX_RETRIES_PROP + "=5");
        System.out.println("    " + MAX_RETRIES_ENV + "=5");
        System.out.println("    -D" + PARALLEL_DOWNLOADS_PROP + "=8");
        System.out.println("    " + PARALLEL_DOWNLOADS_ENV + "=8");

        System.out.println("\n  Cache Directory:");
        System.out.println("    -D" + CACHE_DIR_PROP + "=/custom/cache/path");
        System.out.println("    " + CACHE_DIR_ENV + "=/custom/cache/path");

        // Initialize configuration to get current settings
        initializeConfiguration();

        System.out.println("\nCURRENT CONFIGURATION:");
        System.out.println("  Log Level: " + currentLogLevel);
        System.out.println("  Download Timeout: " + downloadTimeoutSeconds + " seconds");
        System.out.println("  Max Download Size: " + formatBytes(maxDownloadSize));
        System.out.println("  Max Retries: " + maxRetries);
        System.out.println("  Parallel Downloads: " + parallelDownloads);

        try {
            Path currentCacheDir = getCacheDir();
            System.out.println("  Cache Directory: " + currentCacheDir);

            // Show cache statistics
            if (Files.exists(currentCacheDir)) {
                File[] cacheFiles = currentCacheDir.toFile().listFiles((dir, name) -> name.endsWith(".jar"));
                if (cacheFiles != null && cacheFiles.length > 0) {
                    System.out.println("\nCACHE STATISTICS:");
                    System.out.println("  Cached Dependencies: " + cacheFiles.length);

                    long totalSize = 0;
                    for (File file : cacheFiles) {
                        totalSize += file.length();
                    }
                    System.out.println("  Total Cache Size: " + formatBytes(totalSize));

                    System.out.println("\nCACHED DEPENDENCIES:");
                    for (File file : cacheFiles) {
                        System.out.println("  " + file.getName() + " (" + formatBytes(file.length()) + ")");
                    }
                } else {
                    System.out.println("  Cache Status: Empty");
                }
            } else {
                System.out.println("  Cache Status: Not created yet");
            }
        } catch (IOException e) {
            System.out.println("  Cache Directory: Error accessing cache - " + e.getMessage());
        }

        System.out.println("\nTRUSTED REPOSITORIES:");
        for (String repo : trustedRepos) {
            System.out.println("  " + repo);
        }

        System.out.println("\nEXAMPLES:");
        System.out.println("  # Basic usage (INFO level logging)");
        System.out.println("  java -javaagent:agent.jar MyScript.java");

        System.out.println("\n  # Verbose logging");
        System.out.println("  java -D" + LOG_LEVEL_PROP + "=VERBOSE -javaagent:agent.jar MyScript.java");

        System.out.println("\n  # Custom cache and repositories");
        System.out.println("  java -D" + CACHE_DIR_PROP + "=/tmp/jars \\");
        System.out.println("       -D" + TRUSTED_REPOS_PROP + "=https://artifactory.mycompany.com/ \\");
        System.out.println("       -javaagent:agent.jar MyScript.java");
    }

    /**
     * Formats a byte count into a human-readable string.
     * <p>
     * This utility method converts raw byte counts into more readable formats
     * using standard binary prefixes (1024-based). It automatically selects
     * the most appropriate unit (B, KB, MB, GB) based on the size.
     * </p>
     *
     * @param bytes The number of bytes to format
     * @return Human-readable string representation (e.g., "1.5 MB", "512.0 KB")
     */
    private static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
        return String.format("%.1f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }
}
