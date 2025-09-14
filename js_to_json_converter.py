#!/usr/bin/env python3
"""
JavaScript to JSON Configuration Converter
Helps convert JavaScript code to JSON-compatible format for Frida configs
"""

import json
import re
import sys

class JSToJSONConverter:
    def __init__(self):
        self.common_scripts = {
            "ssl_pinning_bypass": {
                "description": "Bypass SSL certificate pinning",
                "code": """
Java.perform(function() {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    
    var TrustManager = Java.registerClass({
        name: 'com.frida.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    var trustManager = TrustManager.$new();
    var sslContext = SSLContext.getInstance('TLS');
    sslContext.init(null, [trustManager], null);
    
    console.log('[+] SSL Pinning bypassed');
});
                """.strip()
            },
            
            "root_detection_bypass": {
                "description": "Bypass common root detection methods",
                "code": """
Java.perform(function() {
    // RootBeer library bypass
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() {
            console.log('[+] RootBeer.isRooted() bypassed');
            return false;
        };
    } catch (e) {}
    
    // Common root detection methods
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            if (cmd.includes('su') || cmd.includes('busybox') || cmd.includes('which')) {
                console.log('[+] Blocked root detection command: ' + cmd);
                throw new Error('Command not found');
            }
            return this.exec(cmd);
        };
    } catch (e) {}
    
    console.log('[+] Root detection bypass loaded');
});
                """.strip()
            },
            
            "debug_detection_bypass": {
                "description": "Bypass debug detection",
                "code": """
Java.perform(function() {
    var Debug = Java.use('android.os.Debug');
    
    Debug.isDebuggerConnected.implementation = function() {
        console.log('[+] Debug.isDebuggerConnected() bypassed');
        return false;
    };
    
    // Block gettimeofday checks for debugging detection
    var libc = Module.findExportByName("libc.so", "gettimeofday");
    if (libc) {
        Interceptor.attach(libc, {
            onLeave: function(retval) {
                // Normalize timing to prevent debug detection
            }
        });
    }
    
    console.log('[+] Debug detection bypass loaded');
});
                """.strip()
            },
            
            "frida_detection_bypass": {
                "description": "Bypass Frida detection",
                "code": """
Java.perform(function() {
    // Hook common Frida detection methods
    var System = Java.use('java.lang.System');
    System.getProperty.implementation = function(key) {
        if (key === "java.vm.name") {
            return "Dalvik";
        }
        return this.getProperty(key);
    };
    
    // Block port scanning for Frida server
    var Socket = Java.use('java.net.Socket');
    Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
        if (port === 27042 || port === 27043) {
            console.log('[+] Blocked Frida port scan: ' + host + ':' + port);
            throw new Error('Connection refused');
        }
        return this.$init(host, port);
    };
    
    console.log('[+] Frida detection bypass loaded');
});
                """.strip()
            }
        }
    
    def clean_js_for_json(self, js_code):
        """Clean JavaScript code to be JSON-safe"""
        # Remove extra whitespace and newlines
        js_code = ' '.join(js_code.strip().split())
        
        # Escape quotes for JSON
        js_code = js_code.replace('"', '\\"')
        
        return js_code
    
    def create_config_with_js(self, package_name, target_class, js_scripts):
        """Create a complete config with JavaScript"""
        config = {
            "app": {
                "package_name": package_name,
                "spawn_mode": True
            },
            "targets": [
                {
                    "class_name": target_class,
                    "methods": [".*"],
                    "enabled": True
                }
            ],
            "global_rules": {
                "method_logging": [".*"]
            },
            "custom_javascript": {}
        }
        
        # Add JavaScript scripts
        for script_name, script_config in js_scripts.items():
            config["custom_javascript"][script_name] = {
                "description": script_config.get("description", script_name),
                "enabled": script_config.get("enabled", True),
                "code": self.clean_js_for_json(script_config["code"])
            }
        
        return config
    
    def add_custom_script(self, name, description, js_code, enabled=True):
        """Add a custom JavaScript script"""
        return {
            name: {
                "description": description,
                "enabled": enabled,
                "code": self.clean_js_for_json(js_code)
            }
        }
    
    def generate_ssl_bypass_config(self, package_name):
        """Generate a config specifically for SSL bypass"""
        config = {
            "app": {
                "package_name": package_name,
                "spawn_mode": True
            },
            "targets": [],  # No specific method hooks needed
            "global_rules": {},
            "custom_javascript": {
                "ssl_pinning_bypass": {
                    "description": "Comprehensive SSL Pinning Bypass",
                    "enabled": True,
                    "code": self.clean_js_for_json("""
Java.perform(function() {
    // TrustManager bypass
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    
    var TrustManager = Java.registerClass({
        name: 'com.frida.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    // HttpsURLConnection bypass
    var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
    HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
        console.log('[+] Bypassing HttpsURLConnection hostname verification');
    };
    
    // OkHttp bypass
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[+] Bypassing OkHttp certificate pinning for: ' + hostname);
            return;
        };
    } catch (e) {}
    
    console.log('[+] SSL Pinning bypass loaded');
});
                    """)
                }
            }
        }
        return config
    
    def save_config(self, config, filename):
        """Save configuration to JSON file"""
        with open(filename, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"[+] Configuration saved to {filename}")

def main():
    if len(sys.argv) < 2:
        print("JavaScript to JSON Configuration Converter")
        print("=" * 50)
        print("Usage:")
        print(f"  {sys.argv[0]} ssl-bypass <package_name>")
        print(f"  {sys.argv[0]} custom <package_name> <class_name>")
        print(f"  {sys.argv[0]} list")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} ssl-bypass com.banking.app")
        print(f"  {sys.argv[0]} custom com.app com.app.SecurityManager")
        print(f"  {sys.argv[0]} list")
        sys.exit(1)
    
    converter = JSToJSONConverter()
    command = sys.argv[1]
    
    if command == "list":
        print("Available built-in scripts:")
        print("=" * 30)
        for name, script in converter.common_scripts.items():
            print(f"📜 {name}")
            print(f"   Description: {script['description']}")
            print()
    
    elif command == "ssl-bypass":
        if len(sys.argv) < 3:
            print("[-] Please specify package name")
            sys.exit(1)
        
        package_name = sys.argv[2]
        config = converter.generate_ssl_bypass_config(package_name)
        filename = f"ssl_bypass_{package_name.replace('.', '_')}.json"
        converter.save_config(config, filename)
        
        print(f"✅ SSL bypass configuration created!")
        print(f"📁 File: {filename}")
        print(f"🚀 Run with: python frida_config.py run {filename}")
    
    elif command == "custom":
        if len(sys.argv) < 4:
            print("[-] Please specify package name and class name")
            sys.exit(1)
        
        package_name = sys.argv[2]
        target_class = sys.argv[3]
        
        # Interactive script selection
        print("Select scripts to include:")
        print("=" * 30)
        selected_scripts = {}
        
        for i, (name, script) in enumerate(converter.common_scripts.items(), 1):
            print(f"{i}. {name} - {script['description']}")
            choice = input(f"   Include? (y/n): ").strip().lower()
            if choice == 'y':
                selected_scripts[name] = script
        
        # Ask for custom JavaScript
        print("\nAdd custom JavaScript code? (y/n): ", end="")
        if input().strip().lower() == 'y':
            custom_name = input("Script name: ")
            custom_desc = input("Description: ")
            print("Enter JavaScript code (end with '###' on a new line):")
            
            custom_code_lines = []
            while True:
                line = input()
                if line.strip() == '###':
                    break
                custom_code_lines.append(line)
            
            custom_code = '\n'.join(custom_code_lines)
            selected_scripts[custom_name] = {
                "description": custom_desc,
                "code": custom_code
            }
        
        # Create configuration
        config = converter.create_config_with_js(package_name, target_class, selected_scripts)
        filename = f"custom_{package_name.replace('.', '_')}.json"
        converter.save_config(config, filename)
        
        print(f"✅ Custom configuration created!")
        print(f"📁 File: {filename}")
        print(f"🚀 Run with: python frida_config.py run {filename}")
    
    else:
        print(f"[-] Unknown command: {command}")
        sys.exit(1)