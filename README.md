# Hooky 


<div align="center">
<img src="assets/hooky_icon.png" alt="Description" width="200" height="200">
</div>

**Hooky** is a dynamic analysis tool for mobile application security testing and runtime instrumentation.



## ⭐ Features
- 🔍 **Function Hooking** - Intercept and analyze native (Java & Kotlin) method calls
- 📱 **Multi-Platform** - Android support (iOS coming soon)  
- 🛡️ **Security Testing** - Bypass protections and uncover hidden behaviors
- ⚡ **Easy to Use** - Simple CLI interface for rapid analysis

Perfect for security researchers, penetration testers, and mobile app analysts who need to perform deep runtime inspection and vulnerability assessment.


## 📋 Complete File Structure

Hooky:

```bash
Hooky/
├── hooky_interactive.py         # Interactive method hooking with filtering ANDROID ONLY
├── method_discovery.py          # Method discovery and analysis ANDROID ONLY
├── hooky_easy.py        # Quick utilities and CLI ANDROID ONLY 
├── hooky_native.py      # Quick utilities for native hooking ANDROID & iOS 
├── hooky_config.py              # Configuration-based hooking ANDROID ONLY
├── hooky_automated.py   # Automation and batch processing ANDROID ONLY
├── js_to_json_converter.py      # From JS to JSON for frida_config
└── README.md                    # This usage guide

```

## 🎯 Quick Start

### Requirements
- Python 3.12+
- frida-server 16.7.19 (must be running on target device)
- uv (Python package manager)

### Installation
```bash
uv venv
# Activate virtual environment
# On Unix/macOS:
source .venv/bin/activate

# On Windows:
.venv\Scripts\activate

# Sync dependencies to active/project virtual environment
uv sync
```
### Setup frida-server
```bash
# Download and setup frida-server 16.7.19 on your target device
# For Android:
adb push frida-server-16.7.19-android-arm64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

```

## 🔧 Usage Commands


### method_discovery.py

```bash
uv run python method_discovery.py com.example.app com.example.SecurityManager
uv run python method_discovery.py com.example.app com.example.SecurityManager --suggest
uv run python method_discovery.py com.example.app com.example.SecurityManager --filter 'auth.*'
```

### hooky_easy.py

```bash
# Quick Utilities - Fast testing
uv run hooky_easy.py com.example.app com.example.AuthManager
uv run hooky_easy.py com.example.app 'login.*' 'auth.'
uv run hooky_easy.py --cli
```

### hooky_interactive.py

```bash
# Interactive Hooking - Core functionality
uv run python hooky_interactive.py com.example.app com.example.SecurityManager
uv run python hooky_interactive.py com.example.app com.example.SecurityManager authenticate login
uv run python hooky_interactive.py com.example.app com.example.SecurityManager 'auth.*' 'check.*'
```

### hooky_config.py

```bash
# Configuration-Based Hooking - Advanced automation
uv run python hooky_config.py examples                    # Generate example configs
uv run python hooky_config.py create                      # Interactive config creation
uv run python hooky_config.py run auth_bypass_config.json # Run configuration
uv run python hooky_config.py validate config.json        # Validate before running
uv run python hooky_config.py show config.json           # Inspect config details
uv run python hooky_config.py add-js config.json  
```

### hooky_native.py

```bash
# Frida Native Hooking
uv run python hooky_native.py -l # List available devices
uv run python hooky_native.py -p -d "14ed2fcc" # # List processes on specific device
uv run python hooky_native.py "com.example.app" -m # List native libraries in a running app
uv run python hooky_native.py "1234" -m # List native libraries in a running app
uv run python hooky_native.py "com.example.app" "libnative.so" -f # Discover ALL functions in a library 
uv run python hooky_native.py "1234" "libnative.so" -f # Discover ALL functions in a library 
uv run python hooky_native.py "com.example.app" "libnative.so" -F # Discover ALL functions with detailed info 
uv run python hooky_native.py "1234" "libnative.so" -F # Discover ALL functions with detailed info (NEW!)
uv run python hooky_native.py "com.example.app" "libnative.so" ".*" # Hook Android app by package name (will spawn) - match all functions
uv run python hooky_native.py "1234" "libnative.so" "SSL_.*" # Hook by PID (will attach)
uv run python hooky_native.py "com.example.app" "libnative.so" "Java_.*" -d "14ed2fcc" # Hook with specific USB device
```

## 🚀 Usage Scenarios

### 1. Method Discovery

**Use Case**: Before hooking, explore what methods are available in your target class and get intelligent suggestions

**Discover Available Methods**
```bash
# Basic method discovery
uv run python method_discovery.py com.example.app com.example.AuthManager

# Filter methods by pattern
uv run python method_discovery.py com.example.app com.example.AuthManager --filter 'auth.*'

# Get intelligent filter suggestions based on method analysis
uv run python method_discovery.py com.example.app com.example.AuthManager --suggest

# Save method information for later analysis
uv run python method_discovery.py com.example.app com.example.AuthManager --save methods.json
```

**Method Discovery Output Example**
```
📂 AUTHENTICATION METHODS (5):
  1. authenticate
     Signature: public boolean authenticate(java.lang.String, java.lang.String)
     Parameters: 2
       [0] java.lang.String
       [1] java.lang.String

  2. validateUser
     Signature: public boolean validateUser(java.lang.String)
     Parameters: 1
       [0] java.lang.String

🎯 SUGGESTED METHOD FILTERS:
1. Authentication (5 methods)
   Filter: 'auth.*|login.*|.*password.*|verify.*|validate.*|check.*'
   Usage: uv run python hooky_interactive.py com.example.app com.example.AuthManager 'auth.*|login.*'

2. Boolean Returns (8 methods)
   Filter: 'is.*|has.*|can.*|should.*|check.*'
   Usage: uv run python hooky_interactive.py com.example.app com.example.AuthManager 'is.*|has.*'

🔤 COMMON METHOD WORDS (for custom filters):
   'auth.*' (5 methods), 'validate.*' (3 methods), 'check.*' (8 methods)
```

### 2. Interactive Runtime Modification with Method Filtering 

**Use Case**: You want to intercept only specific methods and modify values in real-time with advanced error handling

```bash
# Hook only authentication-related methods
uv run python hooky_interactive.py com.whatsapp com.whatsapp.security.AuthManager authenticate verify check

# Hook methods using regex patterns
uv run python hooky_interactive.py com.banking.app com.banking.SecurityManager 'auth.*' 'validate.*' 'is.*Valid'

# Error-resistant hooking for problematic apps
uv run python frida_robust_interactive.py com.banking.app com.banking.SecurityManager 'auth.*'
```

**Method Filter Types**
- **Exact match**: `authenticate` (hooks method named exactly "authenticate")
- **Contains match**: `auth` (hooks methods containing "auth")  
- **Regex pattern**: `'auth.*'` (hooks methods starting with "auth")
- **Multiple filters**: `authenticate login verify` (hooks any matching method)

**Enhanced Interactive Options**
```
[INTERCEPTED] WhatsAppSecurity.authenticate
[CALL ID] 1234
========================================
[ARGUMENTS]
  [0] java.lang.String: user123
  [1] java.lang.String: password456

What would you like to do?
1. Continue with original values (observe only)
2. Return TRUE (boolean bypass)
3. Return FALSE (boolean bypass) 
4. Return NULL
5. Return custom string
6. Throw exception (block method)

Enter choice (1-6): 2
[MOD-RET] WhatsAppSecurity.authenticate -> true
```


### 3. Configuration-Based Hooking with JavaScript Support 

**Use Case**: You have predefined modifications AND custom JavaScript you want to apply automatically

**Enhanced Configuration Management**
```bash
# Generate example configurations (now includes JavaScript examples)
uv run python hooky_config.py examples

# Interactive configuration creation with JavaScript support
uv run python hooky_config.py create

# Add JavaScript to existing configuration
uv run python hooky_config.py add-js my_existing_config.json

# Show detailed configuration information
uv run python hooky_config.py show comprehensive_config.json

# Validate configuration including JavaScript
uv run python hooky_config.py validate banking_bypass_config.json

# Run configuration with method hooks AND JavaScript
uv run python hooky_config.py run enhanced_config.json
```

**Enhanced Configuration Example with JavaScript**
```json
{
  "app": {
    "package_name": "com.secure.app",
    "spawn_mode": true
  },
  "targets": [
    {
      "class_name": "com.secure.AuthManager",
      "methods": ["authenticate.*", "check.*"],
      "enabled": true
    }
  ],
  "global_rules": {
    "return_overrides": {
      ".*authenticate.*": {"return_value": true, "value_type": "boolean"},
      ".*checkPassword.*": {"return_value": true, "value_type": "boolean"}
    },
    "input_modifications": {
      ".*setUsername.*": {"param_index": 0, "new_value": "admin", "value_type": "string"}
    },
    "method_logging": [".*auth.*", ".*security.*"]
  },
  "custom_javascript": {
    "ssl_pinning_bypass": {
      "description": "Comprehensive SSL Pinning Bypass",
      "enabled": true,
      "code": "Java.perform(function() { var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager'); var TrustManager = Java.registerClass({ name: 'com.frida.TrustManager', implements: [X509TrustManager], methods: { checkClientTrusted: function(chain, authType) {}, checkServerTrusted: function(chain, authType) {}, getAcceptedIssuers: function() { return []; } } }); console.log('[+] SSL Pinning bypassed'); });"
    },
    "root_detection_bypass": {
      "description": "Root Detection Bypass",
      "enabled": true,
      "code": "Java.perform(function() { try { var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer'); RootBeer.isRooted.implementation = function() { return false; }; } catch(e) {} console.log('[+] Root bypass loaded'); });"
    }
  }
}
```

### 4. JS to JSON Conversion

**Use Case**: You have JavaScript code that you want to include in JSON configurations

**Quick SSL Bypass Generation**
```bash
# Generate SSL bypass configuration in one command
uv run python js_to_json_converter.py ssl-bypass com.banking.app

# Output: ssl_bypass_com_banking_app.json (ready to run)
uv run python hooky_config.py run ssl_bypass_com_banking_app.json
```

**Interactive JavaScript Development**
```bash
# Interactive JavaScript to JSON converter
uv run python js_to_json_converter.py interactive

# Example session:
# 📱 Package name: com.banking.app
# 🎯 Target class: com.banking.AuthManager
# 
# Enter JavaScript code (end with '###'):
# Java.perform(function() {
#     var AuthManager = Java.use('com.banking.AuthManager');
#     AuthManager.authenticate.implementation = function(user, pass) {
#         console.log('[+] Auth bypass for: ' + user);
#         return true;
#     };
# });
# ###
#
# ✅ Configuration created: interactive_auth_bypass_com_banking_app.json
```

**Custom Multi-Script Configuration**
```bash
# Build custom configuration with multiple scripts
uv run python js_to_json_converter.py custom com.secure.app com.secure.SecurityManager

# Interactive selection process:
# Select built-in scripts:
# 1. ssl_pinning_bypass - Comprehensive SSL Pinning Bypass
#    Include? (y/n): y
# 2. root_detection_bypass - Root Detection Bypass
#    Include? (y/n): y
# 3. debug_detection_bypass - Debug Detection Bypass
#    Include? (y/n): n
#
# Add custom JavaScript code? (y/n): y
# [Enter custom code with validation]
#
# ✅ Custom configuration created with 3 scripts
```

**Built-in Script Library**
```bash
# List available built-in scripts
uv run python js_to_json_converter.py list

# Output:
# Available Built-in Scripts:
# ============================
# 1. 📜 ssl_pinning_bypass
#    Description: Comprehensive SSL Pinning Bypass
#    Code preview: Java.perform(function() { var X509TrustManager...
#
# 2. 📜 root_detection_bypass  
#    Description: Bypass common root detection methods
#    Code preview: Java.perform(function() { try { var RootBeer...
```

## 🔧 Advanced Configuration Examples

### Multi-Target Security Bypass Config
```json
{
  "app": {
    "package_name": "com.secure.app",
    "spawn_mode": true
  },
  "targets": [
    {
      "class_name": "com.secure.auth.AuthManager",
      "methods": ["authenticate.*", "verify.*", "check.*"],
      "enabled": true
    },
    {
      "class_name": "com.secure.security.SecurityChecker",
      "methods": ["is.*Root.*", "is.*Debug.*", "check.*Integrity"],
      "enabled": true
    },
    {
      "class_name": "com.secure.crypto.CryptoManager", 
      "methods": [".*encrypt.*", ".*decrypt.*"],
      "enabled": true
    }
  ],
  "global_rules": {
    "return_overrides": {
      ".*authenticate.*": {"return_value": true, "value_type": "boolean"},
      ".*verify.*": {"return_value": true, "value_type": "boolean"},
      ".*isRoot.*": {"return_value": false, "value_type": "boolean"},
      ".*isDebug.*": {"return_value": false, "value_type": "boolean"},
      ".*checkIntegrity.*": {"return_value": true, "value_type": "boolean"}
    },
    "input_modifications": {
      ".*encrypt.*": {"param_index": 0, "new_value": "intercepted_data", "value_type": "string"},
      ".*setUser.*": {"param_index": 0, "new_value": "admin", "value_type": "string"}
    },
    "method_logging": [
      ".*auth.*", ".*security.*", ".*crypto.*", ".*root.*", ".*debug.*"
    ],
    "method_blocks": [
      ".*sendAnalytics.*", ".*reportUsage.*", ".*trackEvent.*"
    ]
  }
}
```

### Privacy-Focused Configuration
```json
{
  "app": {
    "package_name": "com.social.app",
    "spawn_mode": true
  },
  "targets": [
    {
      "class_name": "com.social.location.LocationManager",
      "methods": [".*location.*", ".*gps.*", ".*track.*"],
      "enabled": true
    },
    {
      "class_name": "com.social.analytics.DataCollector",
      "methods": [".*"],
      "enabled": true  
    },
    {
      "class_name": "com.social.contacts.ContactsManager",
      "methods": [".*contact.*", ".*phone.*", ".*address.*"],
      "enabled": true
    }
  ],
  "global_rules": {
    "return_overrides": {
      ".*getLocation.*": {"return_value": null, "value_type": "null"},
      ".*getContacts.*": {"return_value": "[]", "value_type": "string"},
      ".*hasLocationPermission.*": {"return_value": false, "value_type": "boolean"},
      ".*hasContactsPermission.*": {"return_value": false, "value_type": "boolean"}
    },
    "method_blocks": [
      ".*sendAnalytics.*", ".*trackUser.*", ".*collectData.*", ".*uploadUsage.*"
    ],
    "method_logging": [
      ".*location.*", ".*contact.*", ".*permission.*", ".*analytics.*", ".*track.*"
    ]
  }
}
```

## 🐛 Enhanced Troubleshooting

### Common Configuration Issues

#### 1. **"Process not found" Error**
```bash
[-] Process com.example.app not found
```
**Solutions**:
- Make sure the app is installed: `frida-ps -Ua | grep example`
- Use exact package name from `frida-ps -Ua`
- Try spawning instead of attaching: set `"spawn_mode": true`
- Check if app is running: `frida-ps -Ua | grep -i example`

**Enhanced Debugging**:
```bash
# List all apps and find exact package name
frida-ps -Ua | grep -i banking

# Test connection to device
frida-ps -U

# Check device status
adb devices
```

#### 2. **"Class not found" Error**
```bash
[-] Class not found: com.example.SecurityManager
```
**Solutions**:
- Use method discovery to find available classes:
  ```bash
  uv run python method_discovery.py com.example.app com.example.SecurityManager
  ```
- Use class enumeration to find correct names:
  ```bash
  frida -U -f com.example.app --no-pause -q -e "Java.perform(() => { 
    Java.enumerateLoadedClasses({
      onMatch: name => { if(name.includes('Security')) console.log(name); },
      onComplete: () => {}
    });
  });"
  ```
- Check if class loads after specific app actions
- Verify class name with decompiled APK

**Enhanced Class Discovery**:
```javascript
// Advanced class enumeration
Java.perform(function() {
    console.log("[+] Enumerating classes...");
    var classes = Java.enumerateLoadedClassesSync();
    
    classes.filter(name => 
        name.includes("Auth") || 
        name.includes("Security") || 
        name.includes("Login")
    ).forEach(name => console.log("[CLASS] " + name));
});
```

#### 3. **Method Overload Issues**
```bash
[-] Failed to hook method authenticate: overload not found
```
**Solutions**:
- Use method discovery to see exact method signatures:
  ```bash
  uv run python method_discovery.py com.example.app com.example.AuthManager --filter authenticate
  ```
- List all overloads for a method:
  ```javascript
  Java.perform(function() {
      var AuthManager = Java.use('com.example.AuthManager');
      var overloads = AuthManager.authenticate.overloads;
      
      console.log("[+] Found " + overloads.length + " overloads for authenticate:");
      overloads.forEach((overload, index) => {
          console.log("  [" + index + "] " + overload.toString());
      });
  });
  ```
- Hook all overloads generically or specific ones individually

#### 4. **Permission Denied**
```bash
[-] Failed to attach: unable to access process
```
**Solutions**:
- Run as root: `sudo uv run python script.py`
- Enable USB debugging on device
- Trust the computer on device
- Check SELinux settings on rooted devices
- Verify frida-server is running with correct permissions

**Enhanced Permission Debugging**:
```bash
# Check frida-server status
adb shell "ps | grep frida"

# Restart frida-server as root
adb shell "su -c 'killall frida-server'"
adb shell "su -c '/data/local/tmp/frida-server &'"

# Check SELinux status
adb shell getenforce
```

#### 5. **No Methods Hooked with Filters**
```bash
[FRIDA] Hooked 0 methods matching filters
```
**Solutions**:
- Use method discovery to see available methods:
  ```bash
  uv run python method_discovery.py com.example.app com.example.AuthManager
  ```
- Test filter patterns:
  ```bash
  uv run python method_discovery.py com.example.app com.example.AuthManager --filter 'auth.*'
  ```
- Check filter syntax (use quotes for regex: `'auth.*'`)
- Try broader filters first: `auth` instead of `authenticate`
- Use suggested filters from discovery script:
  ```bash
  uv run python method_discovery.py com.example.app com.example.AuthManager --suggest
  ```

#### 6. **JavaScript Syntax Errors in Configuration**
```bash
[-] Invalid configuration: JSON syntax error at line 15
```
**Solutions**:
- Use the JavaScript converter tools:
  ```bash
  uv run python js_to_json_converter.py interactive
  ```
- Validate configuration:
  ```bash
  uv run python hooky_config.py validate my_config.json
  ```
- Check JavaScript code formatting:
  - Ensure proper JSON escaping of quotes
  - Remove newlines from JavaScript code
  - Validate JavaScript syntax separately

#### 7. **Custom JavaScript Runtime Errors**
```bash
[JS ERROR] ReferenceError: 'SomeClass' is not defined
```
**Solutions**:
- Debug with enhanced logging in configuration
- Test JavaScript separately before adding to config
- Use try-catch blocks in custom JavaScript
- Check class availability before use

**Enhanced JavaScript Debugging**:
```javascript
// Safe class loading pattern
Java.perform(function() {
    try {
        var TargetClass = Java.use('com.example.TargetClass');
        console.log('[+] TargetClass loaded successfully');
        
        // Your implementation here
        
    } catch (e) {
        console.log('[-] Failed to load TargetClass: ' + e.message);
    }
});
```

### Debugging Tips

#### Enable Verbose Logging
```python
# Add to your script
import logging
logging.basicConfig(level=logging.DEBUG)

# In Frida script
console.log("[DEBUG] Method called with args:", JSON.stringify(arguments));
```

#### Configuration Validation
```bash
# Comprehensive configuration validation
uv run python hooky_config.py validate comprehensive_config.json

# Show detailed configuration information
uv run python hooky_config.py show comprehensive_config.json

# Test JavaScript syntax separately
uv run python js_to_json_converter.py interactive
```

#### Find Available Classes
```javascript
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(name, handle) {
            if (name.includes("Security") || name.includes("Auth")) {
                console.log("[CLASS] " + name);
            }
        },
        onComplete: function() {
            console.log("[+] Class enumeration complete");
        }
    });
});
```

#### Test Method Existence Before Hooking
```bash
# Use method discovery first
uv run python method_discovery.py com.example.app com.example.SecurityManager --filter 'your_method_pattern'

# Validate filter patterns
uv run python -c "
import re
pattern = 'auth.*'
test_methods = ['authenticate', 'authorize', 'checkAuth', 'login']
for method in test_methods:
    if re.match(pattern, method):
        print(f'✓ {method} matches {pattern}')
    else:
        print(f'✗ {method} does not match {pattern}')
"
```

#### Interactive Configuration Testing
```bash
# Build and test configuration step by step
uv run python hooky_config.py create                    # Create basic config
uv run python hooky_config.py validate test_config.json # Validate
uv run python hooky_config.py add-js test_config.json   # Add JavaScript
uv run python hooky_config.py validate test_config.json # Re-validate
uv run python hooky_config.py run test_config.json      # Test run
```

### Performance Optimization

#### Selective Method Hooking
```bash
# Instead of hooking all methods (slow)
uv run python hooky_interactive.py com.example.app com.example.AuthManager

# Hook only specific methods (fast)
uv run python hooky_interactive.py com.example.app com.example.AuthManager authenticate login verify
```

#### Use Method Discovery for Targeted Hooking
```bash
# Step 1: Discover and get suggestions
uv run python method_discovery.py com.example.app com.example.AuthManager --suggest

# Step 2: Use suggested filters
uv run python hooky_interactive.py com.example.app com.example.AuthManager 'auth.*|login.*'
```

#### Configuration-Based for Repeated Testing
```json
{
  "targets": [
    {
      "class_name": "com.example.AuthManager",
      "methods": ["authenticate", "login"],  // Specific methods only
      "enabled": true
    }
  ],
  "custom_javascript": {
    "optimized_bypass": {
      "enabled": true,
      "code": "// Lightweight, focused JavaScript implementation"
    }
  }
}
```

#### Conditional Logging
```javascript
// Only log important methods
if (methodName.includes("authenticate") || methodName.includes("security")) {
    console.log("[LOG] " + methodName);
}
```

#### JavaScript Performance Best Practices
```javascript
// ✅ Efficient pattern - cache class references
Java.perform(function() {
    var AuthManager = Java.use('com.example.AuthManager');
    
    AuthManager.authenticate.implementation = function(user, pass) {
        console.log('[+] Auth bypass');
        return true;
    };
});

// ❌ Inefficient pattern - avoid heavy operations in hooks
Java.perform(function() {
    AuthManager.authenticate.implementation = function(user, pass) {
        // Don't do this - expensive operation on every call
        Java.enumerateLoadedClasses({ /* ... */ });
        return true;
    };
});
```


## 📊 Success Metrics and Validation

### Validating Hook Success
```bash
# 1. Confirm methods are being called
uv run python hooky_interactive.py com.example.app com.example.AuthManager authenticate
# Look for "INTERCEPTED" messages when using the app

# 2. Verify modifications work  
# Hook authenticate method, set return to always true
# Try logging into app with wrong credentials - should succeed if hook works

# 3. Check performance impact
# Compare app responsiveness with and without hooks
# Use specific filters to minimize performance impact
```


### Common Success Indicators
- ✅ Methods appear in "INTERCEPTED" messages when app features are used
- ✅ Modifications change app behavior as expected  
- ✅ App remains responsive and stable
- ✅ No JavaScript errors in Frida output
- ✅ Hook survives app restarts (with spawn mode)

### Common Failure Indicators  
- ❌ No "INTERCEPTED" messages despite using app features
- ❌ JavaScript errors about method not found
- ❌ App crashes or becomes unresponsive
- ❌ Modifications don't affect app behavior
- ❌ Methods found in discovery but not hooked successfully

This completes the comprehensive documentation for the Frida Method Interceptor toolkit with all the new method filtering and discovery capabilities!


## 📚 Resources

- **Frida Documentation**: https://frida.re/docs/
- **Android Reverse Engineering**: https://github.com/android/security-samples
- **iOS Security**: https://github.com/OWASP/owasp-mastg
- **Method Signature Reference**: https://docs.oracle.com/javase/tutorial/reflect/
- **Regex Testing**: https://regex101.com/ (for testing method filter patterns)


## 🤝 Contributing

Feel free to extend these scripts with additional features:
- Custom data type support
- GUI interface
- Database logging
- Network interception
- Advanced pattern matching
- Method signature analysis
- Cross-platform support (iOS)     