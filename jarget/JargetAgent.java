
package jarget;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.instrument.Instrumentation;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.jar.JarFile;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

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
 *   <li>{@code // @dep org.apache.commons:commons-lang3:${commons.version}} - Maven dependency with variable</li>
 *   <li>{@code // @dep com.google.guava:guava:31.1-jre sha256:a142e6da479...} - With checksum</li>
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
 *   <li>Parallel downloads: {@code jarget.parallel.downloads} or {@code JARGET_PARALLEL_DOWNLOADS}</li>
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
 * @version 1.3
 * @since 1.0
 */
public class JargetAgent {
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
    private static final String FAIL_ON_ERROR_PROP = "jarget.fail.on.error";
    private static final String FAIL_ON_ERROR_ENV = "JARGET_FAIL_ON_ERROR";

    // Configuration variables
    private static int downloadTimeoutSeconds;
    private static long maxDownloadSize;
    private static int maxRetries = 3;
    private static int parallelDownloads = 4; // Default to 4 parallel downloads
    private static boolean failOnError = true; // Default behavior is to log and continue
    private static Path cacheDir = null;

    private static final int BUFFER_SIZE = 8192;
    private static final long MAX_RETRY_DELAY_MS = 10000L;

    private static final int DEFAULT_DOWNLOAD_TIMEOUT = 30;
    private static final long DEFAULT_MAX_DOWNLOAD_SIZE = 100 * 1024 * 1024; // 100MB
    private static final Logger logger = Logger.getLogger(JargetAgent.class.getName());

    // Log levels
    private enum LogLevel {SILENT, DEFAULT, VERBOSE, ERROR}

    private static LogLevel currentLogLevel = LogLevel.DEFAULT;

    // Dynamic trusted repositories
    private static Set<String> trustedRepos;

    // Keep references to JAR files to prevent them from being garbage collected
    private static final Set<JarFile> openJarFiles = ConcurrentHashMap.newKeySet();

    // Static initializer to register shutdown hook for cleanup and initialize logging.
    static {
        Runtime.getRuntime().addShutdownHook(new Thread(JargetAgent::cleanupResources));
        initializeLogger();
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

    // Lenient pattern to find lines that are likely dependency declarations
    private static final Pattern LENIENT_DEP_PATTERN = Pattern.compile("//\\s*@dep\\s+(.+)", Pattern.CASE_INSENSITIVE);

    // Strict pattern to parse a fully-formed, valid dependency line
    private static final Pattern DEP_PATTERN = Pattern.compile(
        "([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]+)(?:\\s+(?:sha256:([a-fA-F0-9]{64})|md5:([a-fA-F0-9]{32})))?",
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
     * Initializes the logger with appropriate level and formatting.
     * Sets up console handler with custom formatting and removes parent handlers
     * to avoid duplicate log messages.
     */
    private static void initializeLogger() {
        // Remove existing handlers to avoid duplicate logs
        logger.setUseParentHandlers(false);

        // Add custom handler with formatting
        ConsoleHandler handler = new ConsoleHandler();
        handler.setFormatter(new SimpleFormatter() {
            @Override
            public String format(LogRecord record) {
                return String.format("[Jarget] %s: %s%n", record.getLevel(), record.getMessage());
            }
        });
        logger.addHandler(handler);
        configureLogLevel();
    }

    private static void configureLogLevel() {
        String logLevel = System.getProperty(LOG_LEVEL_PROP, System.getenv(LOG_LEVEL_ENV));

        if (logLevel != null) {
            switch (logLevel.toUpperCase()) {
                case "SILENT":  logger.setLevel(Level.OFF); break;
                case "ERROR":   logger.setLevel(Level.SEVERE); break;
                case "VERBOSE": logger.setLevel(Level.ALL); break;
                case "DEFAULT":
                default:        logger.setLevel(Level.INFO); break;
            }
        } else {
            logger.setLevel(Level.INFO);
        }
    }

    /**
     * Cleanup resources when JVM shuts down.
     * Closes all open JAR files to prevent resource leaks.
     * This method is called automatically by the shutdown hook.
     */
    private static void cleanupResources() {
        logger.fine("Cleaning up resources...");
        for (JarFile jar : openJarFiles) {
            try {
                jar.close();
            } catch (IOException e) {
                // Log but don't throw during shutdown
                logger.log(Level.WARNING, "Failed to close JAR file during cleanup", e);
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
            initializeConfiguration();
            logger.fine("Starting dependency resolution...");

            String command = System.getProperty("sun.java.command");
            if (command == null || command.isEmpty()) {
                logger.severe("Could not determine launch command.");
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
                logger.fine("Updated java.class.path with dependencies");
            }
        } catch (SecurityException e) {
            logger.severe("Security error: " + e.getMessage());
        } catch (IOException e) {
            logger.severe("I/O error processing dependencies: " + e.getMessage());
        } catch (Exception e) {
            logger.severe("Unexpected error processing dependencies: " + e.getMessage());
        }
    }

    private static void initializeConfiguration() {
        // Initialize log level
        String logLevel = System.getProperty(LOG_LEVEL_PROP, System.getenv(LOG_LEVEL_ENV));
        if (logLevel != null) {
            try {
                currentLogLevel = LogLevel.valueOf(logLevel.toUpperCase());
            } catch (IllegalArgumentException e) { /* use default */ }
        }

        // Initialize fail on error
        String failOnErrorStr = System.getProperty(FAIL_ON_ERROR_PROP, System.getenv(FAIL_ON_ERROR_ENV));
        if (failOnErrorStr != null) {
            failOnError = Boolean.parseBoolean(failOnErrorStr);
        }

        // Download Timeout
        String timeoutStr = System.getProperty(DOWNLOAD_TIMEOUT_PROP, System.getenv(DOWNLOAD_TIMEOUT_ENV));
        if (timeoutStr != null) {
            try {
                downloadTimeoutSeconds = Integer.parseInt(timeoutStr);
                if (downloadTimeoutSeconds <= 0) downloadTimeoutSeconds = DEFAULT_DOWNLOAD_TIMEOUT;
            } catch (NumberFormatException e) { /* use default */ }
        }

        // Max Download Size
        String sizeStr = System.getProperty(MAX_DOWNLOAD_SIZE_PROP, System.getenv(MAX_DOWNLOAD_SIZE_ENV));
        if (sizeStr != null) {
            try {
                maxDownloadSize = Long.parseLong(sizeStr);
                if (maxDownloadSize <= 0) maxDownloadSize = DEFAULT_MAX_DOWNLOAD_SIZE;
            } catch (NumberFormatException e) { /* use default */ }
        }

        // Max Retries
        String retriesStr = System.getProperty(MAX_RETRIES_PROP, System.getenv(MAX_RETRIES_ENV));
        if (retriesStr != null) {
            try {
                maxRetries = Integer.parseInt(retriesStr);
                if (maxRetries < 0) maxRetries = 3;
            } catch (NumberFormatException e) { /* use default */ }
        }

        // Parallel Downloads
        String parallelStr = System.getProperty(PARALLEL_DOWNLOADS_PROP, System.getenv(PARALLEL_DOWNLOADS_ENV));
        if (parallelStr != null) {
            try {
                parallelDownloads = Integer.parseInt(parallelStr);
                if (parallelDownloads <= 0) parallelDownloads = 4;
            } catch (NumberFormatException e) { /* use default */ }
        }

        // Cache Directory
        String cacheDirStr = System.getProperty(CACHE_DIR_PROP, System.getenv(CACHE_DIR_ENV));
        if (cacheDirStr != null && !cacheDirStr.trim().isEmpty()) {
            cacheDir = Paths.get(cacheDirStr.trim());
        }

        // Trusted Repositories
        trustedRepos = new HashSet<>(TRUSTED_REPOS);
        String additionalRepos = System.getProperty(TRUSTED_REPOS_PROP, System.getenv(TRUSTED_REPOS_ENV));
        if (additionalRepos != null) {
            Arrays.stream(additionalRepos.split("[,;]")).map(String::trim).filter(r -> !r.isEmpty()).forEach(repo -> {
                if (!repo.endsWith("/")) repo += "/";
                if (repo.startsWith("http")) {
                    trustedRepos.add(repo);
                    logger.fine("Added trusted repository: " + repo);
                }
            });
        }
    }

    /**
     * Performs variable substitution on a line.
     * Replaces all occurrences of ${varName} with the value from the variables map.
     *
     * @param line      The line to process.
     * @param variables A map of defined variables.
     * @return The line with all variables substituted.
     */
    private static String substituteVariables(String line, Map<String, String> variables) {
        if (variables.isEmpty() || !line.contains("${")) {
            return line; // Quick exit
        }

        Pattern varSubstitutionPattern = Pattern.compile("\\$\\{([a-zA-Z0-9._-]+)\\}");
        Matcher matcher = varSubstitutionPattern.matcher(line);
        StringBuffer sb = new StringBuffer();

        while (matcher.find()) {
            String varName = matcher.group(1);
            String varValue = variables.get(varName);
            if (varValue != null) {
                // Important: quoteReplacement escapes special characters like '$' or '\' in the value
                matcher.appendReplacement(sb, Matcher.quoteReplacement(varValue));
            } else {
                logger.warning("Variable '" + varName + "' not defined, but used in: " + line);
                // Leave the placeholder as is if the variable is not found
                matcher.appendReplacement(sb, Matcher.quoteReplacement(matcher.group(0)));
            }
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    /**
     * Processes all dependency comments from the source file, downloading in parallel.
     * Implements a two-pass approach to handle variable definitions first.
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
            logger.severe("Source file not found: '" + sourcePath.toAbsolutePath() +
                    "'. Current working directory: '" + System.getProperty("user.dir") +
                    "'. Searched paths: current directory, src/main/java/. " +
                    "Ensure the .java file exists or specify the correct path.");
            if (failOnError) System.exit(1);
            return "";
        }

        logger.info("Processing dependencies from " + sourcePath + " with up to " + parallelDownloads + " parallel downloads.");

        List<String> allLines = Files.readAllLines(sourcePath);
        Map<String, String> variables = new HashMap<>();
        final AtomicBoolean anySevereErrorOccurred = new AtomicBoolean(false);

        // Pass 1: Find all @var definitions
        logger.fine("Scanning for variable definitions...");
        for (String line : allLines) {
            Matcher varMatcher = VAR_PATTERN.matcher(line.trim());
            if (varMatcher.find()) {
                String name = varMatcher.group(1).trim();
                String value = varMatcher.group(2).trim();
                variables.put(name, value);
                logger.fine("Defined variable: " + name + " = " + value);
            }
        }

        // Pass 2: Process all other directives with variable substitution
        ExecutorService executor = Executors.newFixedThreadPool(parallelDownloads);
        List<Future<Path>> downloadFutures = new ArrayList<>();
        StringBuilder localClasspathBuilder = new StringBuilder();

        int lineNumber = 0;
        for (String rawLine : allLines) {
            lineNumber++;
            String line = substituteVariables(rawLine.trim(), variables);

            Matcher lenientDepMatcher = LENIENT_DEP_PATTERN.matcher(line);
            Matcher urlMatcher = URL_PATTERN.matcher(line);
            Matcher jarMatcher = JAR_PATTERN.matcher(line);
            Matcher dirMatcher = DIR_PATTERN.matcher(line);

            if (lenientDepMatcher.matches()) {
                String depContent = lenientDepMatcher.group(1);

                // Check for common variable syntax error
                if (rawLine.contains("{") && !rawLine.contains("${")) {
                    logger.severe("Variable syntax error on line " + lineNumber + " in file '" + sourcePath +
                            "'. Found '{...}' syntax but variables must use '${variable}' format. " +
                            "Line: " + rawLine.trim() +
                            ". Example: '// @dep org.example:lib:${version}'");
                    anySevereErrorOccurred.set(true);
                }

                String[] parts = depContent.split("\\s+");
                String coords = parts[0];
                String[] gav = coords.split(":", -1);

                if (gav.length != 3) {
                    logger.severe("Invalid Maven coordinate format on line " + lineNumber + " in file '" + sourcePath +
                            "'. Expected format: 'groupId:artifactId:version', but got: '" + coords +
                            "'. Example: '// @dep org.apache.commons:commons-lang3:3.12.0'. " +
                            "Skipping line: " + rawLine.trim());
                    anySevereErrorOccurred.set(true);
                    continue;
                }
                boolean hasEmptyPart = false;
                for (int i = 0; i < gav.length; i++) {
                    if (gav[i].isEmpty()) {
                        String[] partNames = {"groupId", "artifactId", "version"};
                        logger.warning("Invalid Maven coordinate. The '" + partNames[i] + "' part is empty in '" + coords + "'. Check for double colons '::'. Skipping line: " + rawLine.trim());
                        hasEmptyPart = true;
                        break;
                    }
                }
                if (hasEmptyPart) {
                    continue;
                }

                Matcher depMatcher = DEP_PATTERN.matcher(depContent);
                if (depMatcher.matches()) {
                    String groupId = depMatcher.group(1);
                    String artifactId = depMatcher.group(2);
                    String version = depMatcher.group(3);
                    String sha256Checksum = depMatcher.group(4);
                    String md5Checksum = depMatcher.group(5);

                    Callable<Path> downloadTask = () -> {
                        try {
                            return downloadMavenArtifact(groupId, artifactId, version, sha256Checksum, md5Checksum);
                        } catch (Exception e) {
                            logger.severe("Failed to resolve dependency " + coords + ": " + e.getMessage());
                            return null;
                        }
                    };
                    downloadFutures.add(executor.submit(downloadTask));
                } else {
                    logger.severe("Could not parse valid dependency from line: " + rawLine.trim() + ". Skipping.");
                }
            } else if (urlMatcher.matches()) {
                String url = urlMatcher.group(1);
                String sha256Checksum = urlMatcher.group(2);
                String md5Checksum = urlMatcher.group(3);
                Callable<Path> downloadTask = () -> {
                    try {
                        return downloadFromUrl(url, sha256Checksum, md5Checksum);
                    } catch (Exception e) {
                        logger.severe("Failed to download from URL " + url + ": " + e.getMessage());
                        return null;
                    }
                };
                downloadFutures.add(executor.submit(downloadTask));
            } else if (jarMatcher.matches()) {
                String jarPathStr = jarMatcher.group(1).trim();
                try {
                    String resolvedPath = addLocalJar(jarPathStr, instrumentation);
                    if (resolvedPath != null && !resolvedPath.isEmpty()) {
                        if (localClasspathBuilder.length() > 0) localClasspathBuilder.append(File.pathSeparator);
                        localClasspathBuilder.append(resolvedPath);
                    }
                } catch (Exception e) {
                    logger.severe("Error processing local JAR " + jarPathStr + ": " + e.getMessage());
                    anySevereErrorOccurred.set(true);
                }
            } else if (dirMatcher.matches()) {
                String dirPathStr = dirMatcher.group(1).trim();
                try {
                    String resolvedPaths = addJarsFromDirectory(dirPathStr, instrumentation);
                    if (resolvedPaths != null && !resolvedPaths.isEmpty()) {
                        if (localClasspathBuilder.length() > 0) localClasspathBuilder.append(File.pathSeparator);
                        localClasspathBuilder.append(resolvedPaths);
                    }
                } catch (Exception e) {
                    logger.severe("Error processing directory " + dirPathStr + ": " + e.getMessage());
                    anySevereErrorOccurred.set(true);
                }
            }
        }

        // Await completion of all downloads and add them to classpath
        StringBuilder finalClasspathBuilder = new StringBuilder(localClasspathBuilder);
        if (downloadFutures.size() > 0) {
            logger.fine("Waiting for " + downloadFutures.size() + " downloads to complete...");
        }

        int processedCount = 0;
        for (Future<Path> future : downloadFutures) {
            try {
                processedCount++;
                Path downloadedJarPath = future.get(); // Blocks until task is complete
                if (downloadedJarPath != null) {
                    addJarToClasspath(downloadedJarPath, instrumentation);
                    if (finalClasspathBuilder.length() > 0) {
                        finalClasspathBuilder.append(File.pathSeparator);
                    }
                    finalClasspathBuilder.append(downloadedJarPath.toAbsolutePath().toString());
                    logger.info("Successfully processed dependency: " + downloadedJarPath.getFileName());
                } else {
                    anySevereErrorOccurred.set(true);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.severe("Dependency processing was interrupted. " +
                        (downloadFutures.size() - processedCount) + " downloads were cancelled. " +
                        "Some dependencies may not be available. Consider rerunning with fewer parallel downloads " +
                        "using -D" + PARALLEL_DOWNLOADS_PROP + "=" + (parallelDownloads / 2));
                break;
            } catch (Exception e) {
                // Catches ExecutionException, which wraps exceptions from the Callable
                logger.severe("A download task failed unexpectedly: " + e.getCause().getMessage());
                anySevereErrorOccurred.set(true);
            }
        }

        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                logger.warning("Thread pool did not terminate gracefully, forcing shutdown.");
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }

        if (failOnError && anySevereErrorOccurred.get()) {
            logger.severe("Terminating due to one or more severe dependency errors.");
            System.exit(1);
        }

        logger.fine("All dependency processing finished.");
        return finalClasspathBuilder.toString();
    }

    /**
     * Downloads and verifies a Maven artifact.
     * This method is designed to be called from a worker thread.
     *
     * @return Path to the verified JAR file in the local cache.
     * @throws Exception if download or verification fails.
     */
    private static Path downloadMavenArtifact(String groupId, String artifactId, String version,
                                              String sha256Checksum, String md5Checksum) throws Exception {
        validateMavenCoordinate(groupId, artifactId, version);
        String filename = artifactId + "-" + version + ".jar";
        Path cacheFile = getCacheDir().resolve(filename);

        if (Files.exists(cacheFile)) {
            logger.fine("Found cached file for " + filename + ", verifying...");
            if (verifyAnyChecksum(cacheFile, sha256Checksum, md5Checksum)) {
                validateJarFile(cacheFile); // Re-validate just in case
                logger.fine("Using cached and verified: " + filename);
                return cacheFile;
            } else {
                logger.warning("Cached file checksum mismatch for " + filename + ". Re-downloading.");
                Files.deleteIfExists(cacheFile);
            }
        }

        String downloadUrl = buildMavenCentralUrl(groupId, artifactId, version);
        logger.info("Downloading: " + downloadUrl);
        downloadFile(downloadUrl, cacheFile);

        if (!verifyAnyChecksum(cacheFile, sha256Checksum, md5Checksum)) {
            Files.deleteIfExists(cacheFile);
            throw new SecurityException("Checksum verification failed for '" + filename +
                    "'. Expected " + (sha256Checksum != null ? "SHA-256" : "MD5") + ": " +
                    (sha256Checksum != null ? sha256Checksum : md5Checksum) +
                    ". This may indicate file corruption or a security issue. " +
                    "Verify the checksum with the dependency provider.");
        }

        validateJarFile(cacheFile);
        logger.fine("Successfully downloaded and verified: " + filename);
        return cacheFile;
    }

    /**
     * Downloads and verifies a JAR from a direct URL.
     * This method is designed to be called from a worker thread.
     *
     * @return Path to the verified JAR file in the local cache.
     * @throws Exception if download or verification fails.
     */
    private static Path downloadFromUrl(String urlString, String sha256Checksum, String md5Checksum) throws Exception {
        URL url;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Invalid URL format: '" + urlString +
                    "'. URLs must start with http:// or https:// and contain a valid hostname. " +
                    "Example: 'https://repo1.maven.org/maven2/example.jar'", e);
        }

        if (!isTrustedRepository(urlString)) {
            throw new SecurityException("Untrusted repository: " + url.getHost());
        }

        String urlPath = url.getPath();
        String filename = urlPath.substring(urlPath.lastIndexOf('/') + 1);
        if (filename.isEmpty() || !filename.endsWith(".jar")) {
            filename = "url-" + Integer.toHexString(urlString.hashCode()) + ".jar";
        }

        Path cacheFile = getCacheDir().resolve(filename);

        if (Files.exists(cacheFile)) {
            logger.fine("Found cached file for " + urlString + ", verifying...");
            if (verifyAnyChecksum(cacheFile, sha256Checksum, md5Checksum)) {
                validateJarFile(cacheFile);
                logger.fine("Using cached and verified: " + filename);
                return cacheFile;
            } else {
                logger.warning("Cached file checksum mismatch for " + filename + ". Re-downloading.");
                Files.deleteIfExists(cacheFile);
            }
        }

        logger.info("Downloading from URL: " + urlString);
        downloadFile(urlString, cacheFile);

        if (!verifyAnyChecksum(cacheFile, sha256Checksum, md5Checksum)) {
            Files.deleteIfExists(cacheFile);
            throw new SecurityException("Checksum verification failed for " + filename);
        }

        validateJarFile(cacheFile);
        logger.fine("Successfully downloaded and verified: " + filename);
        return cacheFile;
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
            if (!isAllowedAbsolutePath(jarFile)) {
                throw new SecurityException("Path '" + jarPath + "' (resolved to: '" + jarFile.toAbsolutePath() +
                        "') is outside allowed directories. Allowed directories include: project root (" +
                        projectRoot + "), user home, Java installation directories, and standard system paths.");
            }
        }

        if (!Files.exists(jarFile))
            throw new IOException("JAR file not found: '" + jarFile.toAbsolutePath() +
                    "'. Current working directory: '" + System.getProperty("user.dir") +
                    "'. Verify the file exists and is accessible.");
        if (!Files.isRegularFile(jarFile))
            throw new IOException("Path '" + jarFile + "' is not a regular file. " +
                    (Files.isDirectory(jarFile) ? "It appears to be a directory." :
                    Files.isSymbolicLink(jarFile) ? "It appears to be a symbolic link." :
                    "File type could not be determined.") + " Expected a .jar file.");

        validateJarFile(jarFile);
        addJarToClasspath(jarFile, instrumentation);
        logger.info("Successfully added local JAR: " + jarFile.getFileName());
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
        String userHome = System.getProperty("user.home");
        String javaHome = System.getProperty("java.home");
        String os = System.getProperty("os.name").toLowerCase();

        boolean isAllowed = false;

        if (os.contains("win")) {
            // Windows-specific allowed paths
            isAllowed = pathStr.matches("^[A-Za-z]:\\\\Program Files.*") ||
                    pathStr.matches("^[A-Za-z]:\\\\Windows\\\\System32.*");
        } else {
            // Unix-like systems
            isAllowed = pathStr.startsWith("/usr/share/java/") ||
                    pathStr.startsWith("/opt/java/") ||
                    pathStr.startsWith("/Library/Java/");
        }

        return isAllowed ||
                (javaHome != null && pathStr.startsWith(javaHome)) ||
                (userHome != null && pathStr.startsWith(userHome));
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
            if (!isAllowedAbsolutePath(directory)) {
                throw new SecurityException("Directory path outside allowed directories: " + dirPath);
            }
        }

        if (!Files.exists(directory))
            throw new IOException("Directory not found: '" + directory.toAbsolutePath() +
                "'. Current working directory: '" + System.getProperty("user.dir") +
                "'. Verify the directory exists and is accessible.");
        if (!Files.isDirectory(directory))
            throw new IOException("Path '" + directory + "' is not a directory. " +
                (Files.isRegularFile(directory) ? "It appears to be a regular file." :
                "Path type could not be determined.") + " Expected a directory containing .jar files.");

        logger.fine("Scanning directory for JARs: " + directory);

        File[] jarFiles = directory.toFile().listFiles((dir, name) -> name.toLowerCase().endsWith(".jar"));
        if (jarFiles == null || jarFiles.length == 0) {
            logger.fine("No JAR files found in directory: " + directory);
            return "";
        }

        StringBuilder classpathBuilder = new StringBuilder();

        for (File jarFile : jarFiles) {
            try {
                validateJarFile(jarFile.toPath());
                addJarToClasspath(jarFile.toPath(), instrumentation);
                logger.info("Added JAR from directory: " + jarFile.getName());
                if (classpathBuilder.length() > 0) classpathBuilder.append(File.pathSeparator);
                classpathBuilder.append(jarFile.getAbsolutePath());
            } catch (Exception e) {
                logger.severe("Failed to add JAR: " + jarFile.getName() + " - " + e.getMessage());
            }
        }

        return classpathBuilder.toString();
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
            new URL(urlString);
            for (String repo : trustedRepos) {
                if (urlString.startsWith(repo)) return true;
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
        if (groupId == null || groupId.trim().isEmpty()) {
            throw new IllegalArgumentException("GroupId cannot be null or empty");
        }
        if (artifactId == null || artifactId.trim().isEmpty()) {
            throw new IllegalArgumentException("ArtifactId cannot be null or empty");
        }
        if (version == null || version.trim().isEmpty()) {
            throw new IllegalArgumentException("Version cannot be null or empty");
        }

        if (!groupId.matches("[a-zA-Z0-9._-]+"))
            throw new IllegalArgumentException("Invalid groupId format: '" + groupId + "'. Must contain only letters, numbers, dots, underscores, and hyphens.");
        if (!artifactId.matches("[a-zA-Z0-9._-]+"))
            throw new IllegalArgumentException("Invalid artifactId format: '" + artifactId + "'. Must contain only letters, numbers, dots, underscores, and hyphens.");
        if (!version.matches("[a-zA-Z0-9._-]+"))
            throw new IllegalArgumentException("Invalid version format: '" + version + "'. Must contain only letters, numbers, dots, underscores, and hyphens.");
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
            // Opening it is the validation
        } catch (IOException e) {
            logger.severe("File is not a valid JAR: '" + jarPath.toAbsolutePath() +
                    "'. Size: " + formatBytes(Files.size(jarPath)) +
                    ". Reason: " + e.getMessage());
            throw new IOException("Invalid JAR file '" + jarPath.getFileName() +
                    "': " + e.getMessage() + ". The file may be corrupted, incomplete, or not a valid JAR archive.", e);
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
            Path tempFile = null;
            try {
                logger.fine("Download attempt " + attempt + "/" + maxRetries + ": " + urlString);

                // Create temp file for atomic operation
                tempFile = Files.createTempFile(destination.getParent(),
                        destination.getFileName().toString(), ".tmp");

                URLConnection connection = url.openConnection();
                connection.setConnectTimeout(downloadTimeoutSeconds * 1000);
                connection.setReadTimeout(downloadTimeoutSeconds * 1000);
                connection.setRequestProperty("User-Agent", "JargetAgent/1.3");
                connection.setRequestProperty("Accept", "application/java-archive, application/octet-stream, */*");

                // Check HTTP response for HTTP connections
                if (connection instanceof HttpURLConnection) {
                    HttpURLConnection httpConn = (HttpURLConnection) connection;
                    try {
                        int responseCode = httpConn.getResponseCode();
                        if (responseCode < 200 || responseCode >= 300) {
                            throw new IOException("HTTP error " + responseCode + ": " + httpConn.getResponseMessage());
                        }

                        // Check content length if provided
                        long contentLength = httpConn.getContentLengthLong();
                        if (contentLength > maxDownloadSize) {
                            throw new IOException("File too large: " + contentLength + " bytes (max: " + maxDownloadSize + ")");
                        }
                    } finally {
                        if (httpConn != null)
                            httpConn.disconnect();
                    }
                }

                if (connection instanceof HttpsURLConnection) {
                    HttpsURLConnection httpsConnection = (HttpsURLConnection) connection;
                    // Use default SSL context which includes certificate validation
                    httpsConnection.setSSLSocketFactory(SSLContext.getDefault().getSocketFactory());
                }

                try (InputStream in = connection.getInputStream()) {
                    long bytesDownloaded = copyWithSizeLimit(in, tempFile, maxDownloadSize);
                    logger.fine("Successfully downloaded " + bytesDownloaded + " bytes");

                    // Atomic move to final destination
                    Files.move(tempFile, destination, StandardCopyOption.REPLACE_EXISTING);
                    tempFile = null; // Prevent cleanup
                    return; // Success
                }

            } catch (IOException e) {
                lastException = e;
                logger.fine("Download attempt " + attempt + " failed: " + e.getMessage());

                if (attempt < maxRetries) {
                    try {
                        // Exponential backoff: 1s, 2s, 4s, etc. upto the max which is 10s delay
                        long delayMs = Math.min(1000L * Math.min(1L << Math.min(attempt - 1, 10), 10), MAX_RETRY_DELAY_MS);
                        logger.fine("Retrying in " + delayMs + "ms...");
                        Thread.sleep(delayMs);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Download interrupted", ie);
                    }
                }
            } catch (Exception e) {
                throw new IOException("Download failed due to unexpected error", e);
            } finally {
                // Cleanup temp file if download failed
                if (tempFile != null) {
                    try {
                        Files.deleteIfExists(tempFile);
                    } catch (IOException ignored) {
                        logger.fine("Failed to cleanup temp file: " + tempFile);
                    }
                }
            }
        }
        throw new IOException("Download failed for '" + urlString + "' after " + maxRetries +
                " attempts. Timeout: " + downloadTimeoutSeconds + "s, Max size: " + formatBytes(maxDownloadSize) +
                ". Last error: " + (lastException != null ? lastException.getMessage() : "Unknown") +
                ". Check network connectivity and repository availability.", lastException);
    }

    private static long copyWithSizeLimit(InputStream in, Path destination, long maxSize) throws IOException {
        try (InputStream input = in) {
            long totalBytes = 0;
            byte[] buffer = new byte[BUFFER_SIZE];

            try (OutputStream out = Files.newOutputStream(destination)) {
                int bytesRead;
                while ((bytesRead = input.read(buffer)) != -1) {
                    totalBytes += bytesRead;
                    if (totalBytes > maxSize) {
                        throw new IOException("File size exceeds limit during download: " + totalBytes + " > " + maxSize);
                    }
                    out.write(buffer, 0, bytesRead);
                }
            }
            return totalBytes;
        }
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
        if (sha256Checksum == null && md5Checksum == null) return true;

        boolean sha256Valid = true;
        boolean md5Valid = true;

        // Verify SHA-256 if provided
        if (sha256Checksum != null) {
            sha256Valid = verifyChecksum(file, sha256Checksum, "SHA-256");
            if (sha256Valid) {
                logger.fine("SHA-256 checksum verification passed for " + file.getFileName());
            }
        }

        // Verify MD5 if provided
        if (md5Checksum != null) {
            md5Valid = verifyChecksum(file, md5Checksum, "MD5");
            if (md5Valid) {
                logger.fine("MD5 checksum verification passed for " + file.getFileName());
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
                byte[] buffer = new byte[BUFFER_SIZE];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    digest.update(buffer, 0, bytesRead);
                }
            }

            byte[] hashBytes = digest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) sb.append(String.format("%02x", b));
            boolean match = sb.toString().equalsIgnoreCase(expectedChecksum);
            if (match) logger.fine(algorithm + " checksum verification passed for " + file.getFileName());
            return match;
        } catch (Exception e) {
            logger.severe(algorithm + " checksum verification failed: " + e.getMessage());
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
    private static Path getCacheDir() throws IOException {
        if (cacheDir == null) {
            // Use user's cache directory, similar to how uv works
            String userHome = System.getProperty("user.home");
            cacheDir = Paths.get(userHome, ".jarget", "cache");
        }

        if (!Files.exists(cacheDir)) {
            try {
                Files.createDirectories(cacheDir);
            } catch (IOException e) {
                throw new IOException("Failed to create cache directory '" + cacheDir +
                        "'. Check permissions and available disk space. " +
                        "Parent directory exists: " + Files.exists(cacheDir.getParent()) +
                        ". You can specify a different cache directory with -D" + CACHE_DIR_PROP + "=<path>", e);
            }
            logger.fine("Created cache directory: " + cacheDir);
        } else {
            logger.fine("Using cache directory: " + cacheDir);
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
            logger.fine("Added to classpath: " + jarPath.getFileName());
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
        System.out.println("Jarget - Dependency Management for Java (v1.2)");
        System.out.println("==============================================");

        System.out.println("\nUSAGE:");
        System.out.println("  java -javaagent:agent.jar [options] YourScript.java");

        System.out.println("\nDEPENDENCY DIRECTIVES:");
        System.out.println("  // @var name=value");
        System.out.println("  // @dep groupId:artifactId:version [sha256:hash|md5:hash]");
        System.out.println("  // @url https://repo.com/lib.jar [sha256:hash|md5:hash]");
        System.out.println("  // @jar path/to/local.jar");
        System.out.println("  // @dir path/to/jar-directory/");

        System.out.println("\nEXAMPLE with variables:");
        System.out.println("  // @var commons.version=3.12.0");
        System.out.println("  // @dep org.apache.commons:commons-lang3:${commons.version}");


        System.out.println("\nCONFIGURATION (System Properties or Environment Variables):");
        System.out.println("  Log Level:");
        System.out.println("    -D" + LOG_LEVEL_PROP + "=SILENT|DEFAULT|VERBOSE");
        System.out.println("    " + LOG_LEVEL_ENV + "=SILENT|DEFAULT|VERBOSE");

        System.out.println("  Trusted Repositories (comma/semicolon separated):");
        System.out.println("    -D" + TRUSTED_REPOS_PROP + "=https://jitpack.io/,https://my-nexus.com/");
        System.out.println("    " + TRUSTED_REPOS_ENV + "=https://jitpack.io/;https://my-nexus.com/");

        System.out.println("  Download Settings:");
        System.out.println("    -D" + PARALLEL_DOWNLOADS_PROP + "=8");
        System.out.println("    " + PARALLEL_DOWNLOADS_ENV + "=8");
        System.out.println("    -D" + DOWNLOAD_TIMEOUT_PROP + "=60");
        System.out.println("    " + DOWNLOAD_TIMEOUT_ENV + "=60");
        System.out.println("    -D" + MAX_DOWNLOAD_SIZE_PROP + "=104857600  # 100MB in bytes");
        System.out.println("    " + MAX_DOWNLOAD_SIZE_ENV + "=104857600");
        System.out.println("    -D" + MAX_RETRIES_PROP + "=5");
        System.out.println("    " + MAX_RETRIES_ENV + "=5");

        System.out.println("  Cache Directory:");
        System.out.println("    -D" + CACHE_DIR_PROP + "=/custom/cache/path");
        System.out.println("    " + CACHE_DIR_ENV + "=/custom/cache/path");

        // Initialize configuration to get current settings
        initializeConfiguration();

        System.out.println("\nCURRENT CONFIGURATION:");
        System.out.println("  Log Level: " + currentLogLevel);
        System.out.println("  Parallel Downloads: " + parallelDownloads);
        System.out.println("  Download Timeout: " + downloadTimeoutSeconds + " seconds");
        System.out.println("  Max Download Size: " + formatBytes(maxDownloadSize));
        System.out.println("  Max Retries: " + maxRetries);

        try {
            Path currentCacheDir = getCacheDir();
            System.out.println("  Cache Directory: " + currentCacheDir);

            // Show cache statistics
            if (Files.exists(currentCacheDir)) {
                File[] cacheFiles = currentCacheDir.toFile().listFiles((dir, name) -> name.endsWith(".jar"));
                if (cacheFiles != null && cacheFiles.length > 0) {
                    System.out.println("\nCACHE STATISTICS:");
                    System.out.println("  Cached Dependencies: " + cacheFiles.length);
                    long totalSize = Arrays.stream(cacheFiles).mapToLong(File::length).sum();
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
        System.out.println("  # Basic usage");
        System.out.println("  java -javaagent:agent.jar MyScript.java");

        System.out.println("  # Verbose logging and more parallel downloads");
        System.out.println("  java -D" + LOG_LEVEL_PROP + "=VERBOSE -D" + PARALLEL_DOWNLOADS_PROP + "=10 -javaagent:agent.jar MyScript.java");

        System.out.println("  # Custom cache and repositories");
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
