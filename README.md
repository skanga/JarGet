# JarGet - Single File Java, with libraries, made easy!

A secure Java agent that processes dependency comments similar to `uv` in Python. JarGet automatically resolves and downloads dependencies specified in Java source files using special comment directives, making it easy to manage dependencies without complex build files.

## Features

- **Zero Configuration**: Works out of the box with sensible defaults
- **Multiple Dependency Sources**: Maven Central, local JARs, directories, and direct URLs
- **Security First**: Repository whitelisting, checksum verification, and path traversal protection
- **Intelligent Caching**: Local cache with integrity verification to avoid re-downloads
- **Flexible Configuration**: System properties and environment variables
- **Robust Downloads**: Retry logic with exponential backoff and timeout handling

## Quick Start

1. **Download the pre-compiled [jarget.jar](https://github.com/skanga/JarGet/raw/refs/heads/main/jarget.jar) file from the github repository** (or build from source)
2. **Add dependency comments** to your Java file:
   ```java
   // @dep org.apache.commons:commons-lang3:3.12.0
   // @dep com.google.guava:guava:31.1-jre
   
   import org.apache.commons.lang3.StringUtils;
   import com.google.common.collect.Lists;
   
   public class MyScript {
       public static void main(String[] args) {
           System.out.println(StringUtils.capitalize("hello world"));
           System.out.println(Lists.newArrayList("a", "b", "c"));
       }
   }
   ```
3. **Run with the agent**:
   ```bash
   java -javaagent:jarget.jar MyScript.java
   ```
### **PRO TIP**
You can set the -javaagent as an environment variable via JAVA_TOOL_OPTIONS or _JAVA_OPTIONS and then JarGet will always "just work" without any modifications to the command line. This is shown in the examples below.
   ```bash
   export JAVA_TOOL_OPTIONS="-javaagent:/path/to/your/jarget.jar" 
   java MyScript.java
   ```
NOTE: On windows use 
   ```bash
   set JAVA_TOOL_OPTIONS="-javaagent:/path/to/your/jarget.jar"
   java MyScript.java
   ```

## Dependency Directives

### Maven Dependencies
```java
// @dep groupId:artifactId:version
// @dep org.apache.commons:commons-lang3:3.12.0
// @dep com.google.guava:guava:31.1-jre sha256:a142e6da479257d5b5f6bc4d85640234c3b6fb73ce60ff369bd22b2f3b7c8afd
```

### Local JAR Files
```java
// @jar /path/to/local.jar
// @jar libs/my-utility.jar
// @jar /absolute/path/to/library.jar
```

### JAR Directories
```java
// @dir /path/to/jar-directory
// @dir libs/
// @dir /opt/java/lib/
```

### Direct URL Downloads
```java
// @url https://repo.example.com/lib.jar
// @url https://github.com/user/project/releases/download/v1.0/library.jar sha256:abc123...
```

### Checksum Verification
Add optional checksums for integrity verification:
```java
// @dep org.example:library:1.0 sha256:a142e6da479257d5b5f6bc4d85640234c3b6fb73ce60ff369bd22b2f3b7c8afd
// @dep org.example:library:1.0 md5:5d41402abc4b2a76b9719d911017c592
// @url https://example.com/lib.jar sha256:def456...
```

## Configuration

You can configure JarGet using system properties (`-D`) or environment variables:

### Log Level
```bash
# System property
java -Djarget.log.level=VERBOSE -javaagent:jarget.jar MyScript.java

# Environment variable
export JARGET_LOG_LEVEL=VERBOSE
java -javaagent:jarget.jar MyScript.java
```

Available levels: `SILENT`, `DEFAULT`, `VERBOSE`, `ERROR`

### Trusted Repositories
Add custom Maven repositories (comma or semicolon separated):
```bash
# System property
-Djarget.trusted.repos=https://jitpack.io/,https://artifactory.mycompany.com/

# Environment variable
export JARGET_TRUSTED_REPOS="https://jitpack.io/;https://my-nexus.example.com/"
```

### Download Settings
```bash
# Timeout (seconds)
-Djarget.download.timeout=60
export JARGET_DOWNLOAD_TIMEOUT=60

# Max download size (bytes)
-Djarget.max.download.size=104857600  # 100MB
export JARGET_MAX_DOWNLOAD_SIZE=104857600

# Max retry attempts
-Djarget.max.retries=5
export JARGET_MAX_RETRIES=5
```

### Cache Directory
```bash
# Custom cache location
-Djarget.cache.dir=/custom/cache/path
export JARGET_CACHE_DIR=/custom/cache/path
```

Default: `~/.jarget/cache`

## Security Features

- **Repository Whitelisting**: Only trusted Maven repositories are allowed by default
- **Checksum Verification**: SHA-256 and MD5 checksum support for integrity validation
- **Path Traversal Protection**: Prevents malicious local paths from being loaded
- **Input Validation**: Validates Maven coordinates to prevent injection attacks
- **SSL/TLS Verification**: Proper certificate validation for HTTPS downloads
- **Size Limits**: Configurable maximum download sizes to prevent DoS attacks

### Default Trusted Repositories

- Maven Central (repo1.maven.org, central.sonatype.com)
- Apache Repositories
- Spring Framework Repositories
- Gradle Plugin Portal
- Eclipse, JBoss, Google Maven, Clojars, JitPack

## Usage Examples

### Basic Dependency Management
```java
// @dep org.json:json:20230227
// @dep org.slf4j:slf4j-simple:2.0.7

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Example {
    private static final Logger logger = LoggerFactory.getLogger(Example.class);
    
    public static void main(String[] args) {
        JSONObject obj = new JSONObject();
        obj.put("message", "Hello from JarGet!");
        logger.info("Created JSON: {}", obj.toString());
    }
}
```

### Mixed Dependency Sources
```java
// Maven dependency
// @dep com.fasterxml.jackson.core:jackson-core:2.15.2

// Local JAR
// @jar libs/custom-utility-1.0.jar

// JAR directory
// @dir /opt/company/libs/

// Direct URL with checksum
// @url https://repo.example.com/special-lib.jar sha256:abc123def456...

public class MixedExample {
    // Your code here
}
```

### Enterprise Configuration
```bash
#!/bin/bash
# Enterprise setup with custom repositories and cache

export JARGET_TRUSTED_REPOS="https://artifactory.company.com/;https://nexus.company.com/"
export JARGET_CACHE_DIR="/opt/jarget/cache"
export JARGET_LOG_LEVEL="DEFAULT"
export JARGET_DOWNLOAD_TIMEOUT="120"
export JARGET_MAX_DOWNLOAD_SIZE="209715200"  # 200MB

java -javaagent:jarget.jar MyEnterpriseApp.java
```

## Building from Source

```bash
# Compile the agent
javac -d build jarget/JargetAgent.java

# Create JAR with manifest
echo "Premain-Class: jarget.JargetAgent" > manifest.txt
jar cfm jarget.jar manifest.txt -C build .

# Test the agent
java -javaagent:jarget.jar YourScript.java
```
Or just run the provided `build.sh` or `build.bat` scripts which do essentially the same thing.
## Cache Management

View cache information:
```bash
java -jar jarget.jar
```

Along with help. this will also display:
- Current configuration
- Cache directory location
- Cached dependencies and sizes
- Trusted repositories

Clear cache manually:
```bash
rm -rf ~/.jarget/cache/*
```

## Troubleshooting

### Common Issues

**Dependencies not found:**
- Check Maven coordinates are correct
- Verify repository accessibility
- Enable verbose logging: `-Djarget.log.level=VERBOSE`

**Security errors:**
- Add custom repositories to trusted list
- Verify checksums if provided
- Check file permissions for local JARs

**Download failures:**
- Increase timeout settings
- Check network connectivity
- Verify URL accessibility

**Performance issues:**
- Use local cache effectively
- Consider increasing download size limits
- Use JAR directories for multiple local dependencies

### Debug Mode
```bash
java -Djarget.log.level=VERBOSE -javaagent:jarget.jar MyScript.java
```

## Comparison with Other Tools

| Feature | JarGet | Maven | Gradle | JBang |
|---------|--------|-------|--------|-------|
| Zero config | ✅ | ❌ | ❌ | ✅ |
| Inline dependencies | ✅ | ❌ | ❌ | ✅ |
| Security focus | ✅ | ⚠️ | ⚠️ | ⚠️ |
| Multiple sources | ✅ | ⚠️ | ✅ | ⚠️ |
| Checksum verification | ✅ | ✅ | ✅ | ❌ |
| Local caching | ✅ | ✅ | ✅ | ✅ |

## License

This project is authored by Shiraz Kanga. It is licensed under Apache 2.0 license.

## Contributing

When contributing:
1. Maintain security-first approach
2. Add tests for new features
3. Update documentation
4. Follow existing code style
5. Consider backward compatibility

## Version History

- **1.0**: Initial release with core dependency management features
    - Maven Central support
    - Local JAR and directory support
    - URL downloads with checksum verification
    - Comprehensive security features
    - Configurable caching and repositories
