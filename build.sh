#!/bin/bash

# Build script for Jarget Agent on Unix/Linux/macOS
# This script compiles the Java agent and packages it into a JAR file

set -euo pipefail  # Exit on error, undefined vars, and pipe failures

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Script configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly BUILD_DIR="${SCRIPT_DIR}/build"
readonly SOURCE_DIR="${SCRIPT_DIR}/jarget"
readonly JAR_NAME="jarget.jar"
readonly MANIFEST_FILE="manifest.txt"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Function to check if required tools are available
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    if ! command -v java >/dev/null 2>&1; then
        print_error "Java is not installed or not in PATH"
        exit 1
    fi
    
    if ! command -v javac >/dev/null 2>&1; then
        print_error "Java compiler (javac) is not installed or not in PATH"
        exit 1
    fi
    
    if ! command -v jar >/dev/null 2>&1; then
        print_error "Java archiver (jar) is not installed or not in PATH"
        exit 1
    fi
    
    # Check Java version
    local java_version
    java_version=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2 | cut -d'.' -f1-2)
    print_status "Using Java version: $java_version"
    
    # Warn if Java version is very old
    if [[ "$java_version" < "1.8" ]]; then
        print_warning "Java 8 or higher is recommended for best compatibility"
    fi
}

# Function to clean up previous builds
cleanup_build() {
    print_status "Cleaning up previous builds..."
    
    # Remove old class files
    if [[ -d "$SOURCE_DIR" ]]; then
        find "$SOURCE_DIR" -name "*.class" -type f -delete 2>/dev/null || true
    fi
    
    # Remove old JAR file
    [[ -f "$JAR_NAME" ]] && rm -f "$JAR_NAME"
    
    # Remove old manifest file
    [[ -f "$MANIFEST_FILE" ]] && rm -f "$MANIFEST_FILE"
    
    # Remove build directory
    [[ -d "$BUILD_DIR" ]] && rm -rf "$BUILD_DIR"
    
    print_success "Cleanup complete"
}

# Function to create build directory structure
create_build_dir() {
    print_status "Creating build directory..."
    mkdir -p "$BUILD_DIR"
}

# Function to create the manifest file
create_manifest() {
    print_status "Creating manifest file..."
    
    cat > "$MANIFEST_FILE" << EOF
Premain-Class: jarget.JargetAgent
Main-Class: jarget.JargetAgent
Implementation-Title: Jarget Agent
Implementation-Version: 1.0
Implementation-Vendor: Jarget Team
Specification-Title: Java Dependency Agent
Specification-Version: 1.0
Specification-Vendor: Jarget Team
Created-By: $(java -version 2>&1 | head -n 1)
Built-Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF
    
    print_success "Manifest file created"
}

# Function to compile the Java source files
compile_sources() {
    print_status "Compiling Jarget Agent..."
    
    # Check if source directory exists
    if [[ ! -d "$SOURCE_DIR" ]]; then
        print_error "Source directory '$SOURCE_DIR' not found"
        print_error "Please ensure JargetAgent.java is in the jarget/ subdirectory"
        exit 1
    fi
    
    # Check if main source file exists
    if [[ ! -f "$SOURCE_DIR/JargetAgent.java" ]]; then
        print_error "JargetAgent.java not found in '$SOURCE_DIR'"
        exit 1
    fi
    
    # Compile with appropriate flags
    local javac_args=(
        "-d" "$BUILD_DIR"                    # Output directory
        "-cp" "."                           # Classpath
        "-Xlint:unchecked"                  # Enable unchecked warnings
        "-Xlint:deprecation"                # Enable deprecation warnings
        "$SOURCE_DIR"/*.java                # Source files
    )
    
    if javac "${javac_args[@]}"; then
        print_success "Compilation successful"
    else
        print_error "Compilation failed!"
        exit 1
    fi
    
    # Verify class files were created
    if [[ ! -f "$BUILD_DIR/jarget/JargetAgent.class" ]]; then
        print_error "Expected class file not found after compilation"
        exit 1
    fi
}

# Function to create the JAR file
create_jar() {
    print_status "Creating $JAR_NAME..."
    
    # Change to build directory to avoid including build path in JAR
    pushd "$BUILD_DIR" >/dev/null
    
    # Create JAR with manifest and class files
    if jar cfm "../$JAR_NAME" "../$MANIFEST_FILE" jarget/*.class; then
        popd >/dev/null
        print_success "JAR creation successful"
    else
        popd >/dev/null
        print_error "JAR creation failed!"
        exit 1
    fi
    
    # Verify JAR was created and has reasonable size
    if [[ -f "$JAR_NAME" ]]; then
        local jar_size
        jar_size=$(du -h "$JAR_NAME" | cut -f1)
        print_status "JAR file size: $jar_size"
        
        # Basic sanity check - JAR should be at least 10KB
        local jar_bytes
        jar_bytes=$(stat -c%s "$JAR_NAME" 2>/dev/null || stat -f%z "$JAR_NAME" 2>/dev/null || echo "0")
        if [[ "$jar_bytes" -lt 10240 ]]; then
            print_warning "JAR file seems unusually small ($jar_size). Please verify contents."
        fi
    else
        print_error "JAR file was not created"
        exit 1
    fi
}

# Function to clean up temporary files
cleanup_temp_files() {
    print_status "Cleaning up temporary files..."
    
    # Remove build directory
    [[ -d "$BUILD_DIR" ]] && rm -rf "$BUILD_DIR"
    
    # Remove manifest file
    [[ -f "$MANIFEST_FILE" ]] && rm -f "$MANIFEST_FILE"
    
    print_success "Temporary files cleaned up"
}

# Function to test the JAR file
test_jar() {
    print_status "Testing JAR file..."
    
    # Test that JAR can be executed (should show help)
    if java -jar "$JAR_NAME" >/dev/null 2>&1; then
        print_success "JAR file test passed"
    else
        print_warning "JAR file test failed, but this might be expected behavior"
    fi
    
    # List JAR contents for verification
    print_status "JAR contents:"
    jar tf "$JAR_NAME" | sed 's/^/  /'
}

# Function to display usage information
show_usage() {
    cat << EOF

${GREEN}Build complete! $JAR_NAME is ready to use.${NC}

${BLUE}Usage:${NC}
  java -javaagent:$JAR_NAME YourScript.java

${BLUE}Configuration options:${NC}
  # Verbose logging
  java -Djarget.log.level=VERBOSE -javaagent:$JAR_NAME YourScript.java
  
  # Custom cache directory
  java -Djarget.cache.dir=/tmp/jarget-cache -javaagent:$JAR_NAME YourScript.java
  
  # Additional trusted repositories
  java -Djarget.trusted.repos="https://jitpack.io/,https://my-nexus.com/" \\
       -javaagent:$JAR_NAME YourScript.java

${BLUE}Environment variables (alternative to system properties):${NC}
  export JARGET_LOG_LEVEL=VERBOSE
  export JARGET_CACHE_DIR=/tmp/jarget-cache
  export JARGET_TRUSTED_REPOS="https://jitpack.io/;https://my-nexus.com/"
  java -javaagent:$JAR_NAME YourScript.java

${BLUE}Example Java script with dependencies:${NC}
${YELLOW}  // @dep org.apache.commons:commons-lang3:3.12.0
  // @dep com.google.guava:guava:31.1-jre sha256:a142e6da479f1261dd0ca...
  // @jar libs/mylib.jar
  // @dir external-libs/
  // @url https://repo1.maven.org/maven2/org/json/json/20210307/json-20210307.jar${NC}

${BLUE}For help and cache information:${NC}
  java -jar $JAR_NAME

EOF
}

# Function to handle script interruption
cleanup_on_exit() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        print_error "Build interrupted or failed"
        # Clean up any partial files
        [[ -f "$JAR_NAME" ]] && rm -f "$JAR_NAME"
        [[ -f "$MANIFEST_FILE" ]] && rm -f "$MANIFEST_FILE"
        [[ -d "$BUILD_DIR" ]] && rm -rf "$BUILD_DIR"
    fi
}

# Main build function
main() {
    echo -e "${BLUE}===========================================${NC}"
    echo -e "${BLUE}    Building Jarget Agent for Java       ${NC}"
    echo -e "${BLUE}===========================================${NC}"
    echo
    
    # Set up error handling
    trap cleanup_on_exit ERR INT TERM
    
    # Execute build steps
    check_prerequisites
    cleanup_build
    create_build_dir
    create_manifest
    compile_sources
    create_jar
    cleanup_temp_files
    test_jar
    
    # Clear the trap since we completed successfully
    trap - ERR INT TERM
    
    # Show success message and usage
    show_usage
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi