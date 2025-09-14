#!/usr/bin/env python3
"""
Frida Configuration System with Real-World Examples
Supports JSON configuration files for easy rule management
"""

import json
import yaml
import frida
import sys
import os
from datetime import datetime
import time

class FridaConfig:
    """Configuration manager for Frida hooks"""
    
    def __init__(self, config_file=None):
        self.config = {
            "app": {
                "package_name": "",
                "spawn_mode": True,
                "enable_spawn_gating": False
            },
            "logging": {
                "enabled": True,
                "log_file": None,
                "log_level": "INFO"
            },
            "targets": [],
            "global_rules": {
                "input_modifications": {},
                "return_overrides": {},
                "method_blocks": [],
                "method_logging": []
            }
        }
        
        if config_file:
            self.load_config(config_file)
    
    def load_config(self, file_path):
        """Load configuration from JSON or YAML file"""
        try:
            with open(file_path, 'r') as f:
                if file_path.endswith('.yaml') or file_path.endswith('.yml'):
                    self.config.update(yaml.safe_load(f))
                else:
                    self.config.update(json.load(f))
            print(f"[+] Configuration loaded from {file_path}")
        except Exception as e:
            print(f"[-] Failed to load config: {e}")
    
    def save_config(self, file_path):
        """Save current configuration to file"""
        try:
            with open(file_path, 'w') as f:
                if file_path.endswith('.yaml') or file_path.endswith('.yml'):
                    yaml.dump(self.config, f, default_flow_style=False)
                else:
                    json.dump(self.config, f, indent=2)
            print(f"[+] Configuration saved to {file_path}")
        except Exception as e:
            print(f"[-] Failed to save config: {e}")
    
    def add_target(self, class_name, methods=None):
        """Add a target class to hook"""
        target = {
            "class_name": class_name,
            "methods": methods or [".*"],
            "enabled": True
        }
        self.config["targets"].append(target)
    
    def add_input_rule(self, method_pattern, param_index, new_value, value_type="string"):
        """Add input modification rule"""
        self.config["global_rules"]["input_modifications"][method_pattern] = {
            "param_index": param_index,
            "new_value": new_value,
            "value_type": value_type
        }
    
    def add_return_rule(self, method_pattern, return_value, value_type="string"):
        """Add return value override rule with proper type conversion"""
        
        # Convert value based on type for proper storage
        if value_type == 'boolean':
            if isinstance(return_value, str):
                return_value = return_value.lower() in ['true', '1', 'yes', 'y']
            else:
                return_value = bool(return_value)
        elif value_type == 'int':
            return_value = int(return_value)
        elif value_type == 'double':
            return_value = float(return_value)
        elif value_type == 'null':
            return_value = None
        
        self.config["global_rules"]["return_overrides"][method_pattern] = {
            "return_value": return_value,
            "value_type": value_type
        }

    
    def generate_frida_script(self):
        """Generate Frida JavaScript from configuration"""
        config_json = json.dumps(self.config)
        
        # Start building the script
        script_parts = []
        
        # Add custom JavaScript blocks first (if any)
        if "custom_javascript" in self.config:
            for script_name, script_config in self.config["custom_javascript"].items():
                if script_config.get("enabled", True):
                    script_parts.append(f"""
                    // {script_config.get('description', script_name)}
                    try {{
                        {script_config['code']}
                        console.log('[+] Custom script loaded: {script_name}');
                    }} catch (e) {{
                        console.log('[-] Failed to load custom script {script_name}: ' + e.message);
                    }}
                    """)
        
        # Add startup scripts
        if "startup_scripts" in self.config:
            for startup_script in self.config["startup_scripts"]:
                script_parts.append(f"""
                // {startup_script.get('description', startup_script.get('name', 'startup script'))}
                try {{
                    {startup_script['code']}
                }} catch (e) {{
                    console.log('[-] Startup script error: ' + e.message);
                }}
                """)
        
        # Main configuration-based hook script
        main_script = f"""
        Java.perform(function() {{
            const config = {config_json};
            const hookedMethods = new Set();
            console.log("[+] Starting configured hooks");
            console.log("[+] Targets: " + config.targets.length);
            
            // Helper function to match patterns
            function matchesPattern(text, pattern) {{
                try {{
                    return new RegExp(pattern).test(text);
                }} catch (e) {{
                    return text.includes(pattern);
                }}
            }}
            
            // Hook each target
            config.targets.forEach(function(target) {{
                if (!target.enabled) return;
                
                try {{
                    const targetClass = Java.use(target.class_name);
                    console.log("[+] Found class: " + target.class_name);
                    
                    const methods = targetClass.class.getDeclaredMethods();
                    
                    methods.forEach(function(method) {{
                        const methodName = method.getName();
                        if (methodName.includes('<init>') || methodName.includes('<clinit>')) return;
                        
                        // Check if method matches target patterns
                        let shouldHook = false;
                        target.methods.forEach(function(pattern) {{
                            if (matchesPattern(methodName, pattern)) {{
                                shouldHook = true;
                            }}
                        }});
                        
                        if (!shouldHook) return;
                        
                        try {{
                            const paramTypes = method.getParameterTypes();
                            const paramNames = [];
                            for (let i = 0; i < paramTypes.length; i++) {{
                                paramNames.push(paramTypes[i].getName());
                            }}
                            
                            const fullMethodName = target.class_name + "." + methodName;
                            if (hookedMethods.has(fullMethodName)) return;
                            hookedMethods.add(fullMethodName);
                            
                            const originalMethod = targetClass[methodName].overload.apply(targetClass[methodName], paramNames);
                            
                            targetClass[methodName].overload.apply(targetClass[methodName], paramNames).implementation = function() {{
                                const args = Array.prototype.slice.call(arguments);
                                
                                // Check method logging rules
                                let shouldLog = false;
                                if (config.global_rules && config.global_rules.method_logging) {{
                                    config.global_rules.method_logging.forEach(function(pattern) {{
                                        if (matchesPattern(fullMethodName, pattern)) {{
                                            shouldLog = true;
                                        }}
                                    }});
                                }}
                                
                                if (shouldLog) {{
                                    console.log("[LOG] " + fullMethodName);
                                    for (let i = 0; i < args.length; i++) {{
                                        console.log("  [" + i + "] " + paramNames[i] + ": " + args[i]);
                                    }}
                                }}
                                
                                // Check method blocking rules
                                let shouldBlock = false;
                                if (config.global_rules && config.global_rules.method_blocks) {{
                                    config.global_rules.method_blocks.forEach(function(pattern) {{
                                        if (matchesPattern(fullMethodName, pattern)) {{
                                            shouldBlock = true;
                                        }}
                                    }});
                                }}
                                
                                if (shouldBlock) {{
                                    console.log("[BLOCKED] " + fullMethodName);
                                    return null;
                                }}
                                
                                // Apply input modifications
                                if (config.global_rules && config.global_rules.input_modifications) {{
                                    Object.keys(config.global_rules.input_modifications).forEach(function(pattern) {{
                                        if (matchesPattern(fullMethodName, pattern)) {{
                                            const rule = config.global_rules.input_modifications[pattern];
                                            const paramIndex = rule.param_index;
                                            
                                            if (paramIndex < args.length) {{
                                                const oldValue = args[paramIndex];
                                                
                                                if (rule.value_type === 'string') {{
                                                    args[paramIndex] = rule.new_value;
                                                }} else if (rule.value_type === 'int') {{
                                                    args[paramIndex] = parseInt(rule.new_value);
                                                }} else if (rule.value_type === 'boolean') {{
                                                    args[paramIndex] = rule.new_value;
                                                }} else if (rule.value_type === 'double') {{
                                                    args[paramIndex] = parseFloat(rule.new_value);
                                                }}
                                                
                                                console.log("[MOD-IN] " + fullMethodName + "[" + paramIndex + "] " + oldValue + " -> " + args[paramIndex]);
                                            }}
                                        }}
                                    }});
                                }}
                                
                             // Fixed return override logic with proper boolean handling
                            // Replace the return override section in your generate_frida_script method

                            // Check return overrides
                            let returnOverride = null;
                            if (config.global_rules && config.global_rules.return_overrides) {{
                                Object.keys(config.global_rules.return_overrides).forEach(function(pattern) {{
                                    if (matchesPattern(fullMethodName, pattern)) {{
                                        const rule = config.global_rules.return_overrides[pattern];
                                        
                                        console.log("[DEBUG] Processing return override for: " + fullMethodName);
                                        console.log("[DEBUG] Rule: " + JSON.stringify(rule));
                                        
                                        if (rule.value_type === 'string') {{
                                            returnOverride = rule.return_value;
                                        }} else if (rule.value_type === 'int') {{
                                            returnOverride = parseInt(rule.return_value);
                                        }} else if (rule.value_type === 'boolean') {{
                                            // Proper boolean handling - convert various formats to boolean
                                            const val = rule.return_value;
                                            if (typeof val === 'boolean') {{
                                                returnOverride = val;
                                            }} else if (typeof val === 'string') {{
                                                returnOverride = val.toLowerCase() === 'true';
                                            }} else {{
                                                returnOverride = Boolean(val);
                                            }}
                                            console.log("[DEBUG] Boolean override: " + returnOverride + " (type: " + typeof returnOverride + ")");
                                        }} else if (rule.value_type === 'double') {{
                                            returnOverride = parseFloat(rule.return_value);
                                        }} else if (rule.value_type === 'null') {{
                                            returnOverride = null;
                                        }}
                                    }}
                                }});
                            }}
                            if (returnOverride !== null) {{
                                console.log("[MOD-RET] " + fullMethodName + " -> " + returnOverride + " (type: " + typeof returnOverride + ")");
                                return returnOverride;
                            }} else {{
                                const result = originalMethod.apply(this, args);
                                return result;
                            }}
                            }};
                            
                            console.log("[+] Hooked: " + fullMethodName);
                            
                        }} catch (e) {{
                            console.log("[-] Failed to hook: " + fullMethodName + " - " + e);
                        }}
                    }});
                    
                }} catch (e) {{
                    console.log("[-] Class not found: " + target.class_name);
                }}
            }});
            
            console.log("[+] Configuration loaded, " + hookedMethods.size + " methods hooked");
        }});
        """
        
        script_parts.append(main_script)
        
        return '\n'.join(script_parts)
    
    def add_custom_javascript(self, script_name, description, code, enabled=True):
        """Add custom JavaScript to configuration"""
        if "custom_javascript" not in self.config:
            self.config["custom_javascript"] = {}
        
        self.config["custom_javascript"][script_name] = {
            "description": description,
            "code": code,
            "enabled": enabled
        }

# Example configuration files
EXAMPLE_CONFIGS = {
    "auth_bypass": {
        "app": {
            "package_name": "com.example.secureapp",
            "spawn_mode": True
        },
        "targets": [
            {
                "class_name": "com.example.auth.AuthManager",
                "methods": ["authenticate.*", "login.*", "check.*"],
                "enabled": True
            },
            {
                "class_name": "com.example.security.SecurityChecker", 
                "methods": [".*"],
                "enabled": True
            }
        ],
        "global_rules": {
            "return_overrides": {
                ".*authenticate.*": {"return_value": True, "value_type": "boolean"},
                ".*login.*": {"return_value": True, "value_type": "boolean"},
                ".*checkPassword.*": {"return_value": True, "value_type": "boolean"},
                ".*isValidUser.*": {"return_value": True, "value_type": "boolean"}
            },
            "input_modifications": {
                ".*setUsername.*": {"param_index": 0, "new_value": "admin", "value_type": "string"}
            },
            "method_logging": [".*auth.*", ".*login.*", ".*security.*"]
        }
    },
    
    "crypto_analysis": {
        "app": {
            "package_name": "com.example.cryptoapp"
        },
        "targets": [
            {
                "class_name": "javax.crypto.Cipher",
                "methods": [".*"],
                "enabled": True
            },
            {
                "class_name": "java.security.MessageDigest",
                "methods": [".*"],
                "enabled": True
            }
        ],
        "global_rules": {
            "method_logging": [".*encrypt.*", ".*decrypt.*", ".*digest.*", ".*hash.*"],
            "input_modifications": {
                ".*encrypt.*": {"param_index": 0, "new_value": "intercepted_data", "value_type": "string"}
            }
        }
    },
    
    "network_intercept": {
        "app": {
            "package_name": "com.example.networkapp"
        },
        "targets": [
            {
                "class_name": "okhttp3.OkHttpClient",
                "methods": [".*"],
                "enabled": True
            },
            {
                "class_name": "java.net.URL",
                "methods": ["openConnection"],
                "enabled": True
            }
        ],
        "global_rules": {
            "method_logging": [".*http.*", ".*url.*", ".*connection.*"],
            "return_overrides": {
                ".*isHttpsRequired.*": {"return_value": False, "value_type": "boolean"}
            }
        }
    }
}

class ConfiguredFridaRunner:
    """Run Frida with configuration file"""
    
    def __init__(self, config_file):
        self.config = FridaConfig(config_file)
        self.device = None
        self.session = None
        self.script = None
        
    def run(self):
        """Start Frida with loaded configuration"""
        try:
            package_name = self.config.config["app"]["package_name"]
            spawn_mode = self.config.config["app"].get("spawn_mode", True)
            
            print(f"[+] Connecting to device...")
            self.device = frida.get_usb_device()
            if spawn_mode:
                print(f"[+] Spawning {package_name}...")
                self.pid = self.device.spawn([package_name])
                self.session = self.device.attach(self.pid)
            else:
                print(f"[+] Attaching to {package_name}...")
                self.pid = self.device.spawn([package_name])
                self.session = self.device.attach(self.pid)
            
            # Generate and load script
            script_code = self.config.generate_frida_script()
            self.script = self.session.create_script(script_code)
            self.script.on('message', self._on_message)
            self.script.load()
            self.device.resume(self.pid)

            print("[+] Configuration loaded successfully")
            print("[+] Press Ctrl+C to stop...")
            
            # Keep running
            import sys
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[+] Stopping...")
                
        except Exception as e:
            print(f"[-] Error: {e}")
        finally:
            if self.session:
                self.session.detach()
    
    def _on_message(self, message, data):
        """Handle messages from Frida script"""
        if message['type'] == 'send':
            print(f"[JS] {message['payload']}")
        elif message['type'] == 'error':
            print(f"[ERROR] {message['description']}")

# Configuration file generators
def generate_example_configs():
    """Generate example configuration files"""
    for name, config in EXAMPLE_CONFIGS.items():
        filename = f"{name}_config.json"
        with open(filename, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"[+] Generated {filename}")

def create_custom_config():
    """Interactive configuration creator"""
    config = FridaConfig()
    
    # App configuration
    print("=== App Configuration ===")
    package_name = input("Enter package name: ")
    spawn_mode = input("Spawn new process? (y/n): ").lower() == 'y'
    
    config.config["app"]["package_name"] = package_name
    config.config["app"]["spawn_mode"] = spawn_mode
    
    # Target classes
    print("\n=== Target Classes ===")
    while True:
        class_name = input("Enter class name (or 'done' to finish): ")
        if class_name.lower() == 'done':
            break
        
        methods = input("Enter method patterns (comma-separated, or Enter for all): ").strip()
        if not methods:
            methods = [".*"]
        else:
            methods = [m.strip() for m in methods.split(',')]
        
        config.add_target(class_name, methods)
        print(f"[+] Added target: {class_name}")
    
    # Rules
    print("\n=== Rules Configuration ===")
    
    # Input modification rules
    while True:
        add_input = input("Add input modification rule? (y/n): ").lower()
        if add_input != 'y':
            break
        
        method_pattern = input("Method pattern: ")
        param_index = int(input("Parameter index: "))
        new_value = input("New value: ")
        value_type = input("Value type (string/int/boolean/double): ")
        
        config.add_input_rule(method_pattern, param_index, new_value, value_type)
        print(f"[+] Added input rule for {method_pattern}")
    
    # Return override rules
    while True:
        add_return = input("Add return override rule? (y/n): ").lower()
        if add_return != 'y':
            break
        
        method_pattern = input("Method pattern: ")
        return_value = input("Return value: ")
        value_type = input("Value type (string/int/boolean/double/null): ")
        
        # Convert value based on type with proper boolean handling
        if value_type == 'boolean':
            return_value = return_value.lower() in ['true', '1', 'yes', 'y']
        elif value_type == 'int':
            return_value = int(return_value)
        elif value_type == 'double':
            return_value = float(return_value)
        elif value_type == 'null':
            return_value = None
        
        config.add_return_rule(method_pattern, return_value, value_type)
        print(f"[+] Added return rule for {method_pattern}: {return_value} ({type(return_value).__name__})")
    
    
    # Method logging
    log_patterns = input("Method logging patterns (comma-separated): ").strip()
    if log_patterns:
        config.config["global_rules"]["method_logging"] = [p.strip() for p in log_patterns.split(',')]
    
    # Method blocking
    block_patterns = input("Method blocking patterns (comma-separated): ").strip()
    if block_patterns:
        config.config["global_rules"]["method_blocks"] = [p.strip() for p in block_patterns.split(',')]
    
    # Save configuration
    filename = input("Save configuration as (filename.json): ")
    if not filename.endswith('.json'):
        filename += '.json'
    
    config.save_config(filename)
    print(f"[+] Configuration saved to {filename}")
    
    return config

# Command line interface
def main():
    if len(sys.argv) < 2:
        print("Frida Configuration System")
        print("=" * 30)
        print("Usage:")
        print(f"  {sys.argv[0]} run <config.json>           # Run with config file")
        print(f"  {sys.argv[0]} create                      # Create config interactively") 
        print(f"  {sys.argv[0]} examples                    # Generate example configs")
        print(f"  {sys.argv[0]} validate <config.json>      # Validate config file")
        print(f"  {sys.argv[0]} add-js <config.json>        # Add JavaScript to existing config")
        print(f"  {sys.argv[0]} show <config.json>          # Show config details")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} examples")
        print(f"  {sys.argv[0]} run auth_bypass_config.json")
        print(f"  {sys.argv[0]} create")
        print(f"  {sys.argv[0]} add-js my_config.json")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "run":
        if len(sys.argv) < 3:
            print("[-] Please specify config file")
            sys.exit(1)
        
        config_file = sys.argv[2]
        if not os.path.exists(config_file):
            print(f"[-] Config file not found: {config_file}")
            sys.exit(1)
        
        runner = ConfiguredFridaRunner(config_file)
        runner.run()
        
    elif command == "create":
        create_custom_config()
        
    elif command == "examples":
        generate_example_configs()
        print("[+] Example configurations generated:")
        for name in EXAMPLE_CONFIGS.keys():
            print(f"  - {name}_config.json")
        
        # Also generate JavaScript-enhanced examples
        banking_app_bypass_example()
        social_media_privacy_example()
        print("  - banking_bypass_config.json")
        print("  - privacy_test_config.json")
        
    elif command == "validate":
        if len(sys.argv) < 3:
            print("[-] Please specify config file")
            sys.exit(1)
        
        config_file = sys.argv[2]
        try:
            config = FridaConfig(config_file)
            print(f"[+] Configuration file is valid")
            print(f"[+] Package: {config.config['app']['package_name']}")
            print(f"[+] Targets: {len(config.config['targets'])}")
            print(f"[+] Input rules: {len(config.config['global_rules'].get('input_modifications', {}))}")
            print(f"[+] Return rules: {len(config.config['global_rules'].get('return_overrides', {}))}")
            
            # Show JavaScript scripts
            if 'custom_javascript' in config.config:
                print(f"[+] Custom JavaScript scripts: {len(config.config['custom_javascript'])}")
                for script_name, script_info in config.config['custom_javascript'].items():
                    status = "enabled" if script_info.get('enabled', True) else "disabled"
                    print(f"    - {script_name}: {script_info.get('description', 'No description')} ({status})")
            
            if 'startup_scripts' in config.config:
                print(f"[+] Startup scripts: {len(config.config['startup_scripts'])}")
                
        except Exception as e:
            print(f"[-] Invalid configuration: {e}")
    
    elif command == "add-js":
        if len(sys.argv) < 3:
            print("[-] Please specify config file")
            sys.exit(1)
        
        config_file = sys.argv[2]
        if not os.path.exists(config_file):
            print(f"[-] Config file not found: {config_file}")
            sys.exit(1)
        
        try:
            config = FridaConfig(config_file)
            
            print("Add JavaScript to Configuration")
            print("=" * 35)
            print(f"📁 Config file: {config_file}")
            print(f"📱 Package: {config.config['app']['package_name']}")
            
            # Show existing scripts
            if 'custom_javascript' in config.config:
                print(f"\n📜 Existing scripts: {len(config.config['custom_javascript'])}")
                for name, info in config.config['custom_javascript'].items():
                    print(f"   - {name}: {info.get('description', 'No description')}")
            
            while True:
                add_script = input("\nAdd new JavaScript script? (y/n): ").lower()
                if add_script != 'y':
                    break
                
                script_name = input("Script name: ")
                script_desc = input("Script description: ")
                
                print("Enter JavaScript code (end with '###' on a new line):")
                js_lines = []
                while True:
                    line = input()
                    if line.strip() == '###':
                        break
                    js_lines.append(line)
                
                js_code = '\n'.join(js_lines)
                enabled = input("Enable this script by default? (y/n): ").lower() == 'y'
                
                config.add_custom_javascript(script_name, script_desc, js_code, enabled)
                print(f"[+] Added JavaScript: {script_name}")
            
            # Save updated config
            config.save_config(config_file)
            print(f"[+] Updated configuration saved to {config_file}")
            
        except Exception as e:
            print(f"[-] Error updating config: {e}")
    
    elif command == "show":
        if len(sys.argv) < 3:
            print("[-] Please specify config file")
            sys.exit(1)
        
        config_file = sys.argv[2]
        if not os.path.exists(config_file):
            print(f"[-] Config file not found: {config_file}")
            sys.exit(1)
        
        try:
            config = FridaConfig(config_file)
            
            print("Configuration Details")
            print("=" * 25)
            print(f"📁 File: {config_file}")
            print(f"📱 Package: {config.config['app']['package_name']}")
            print(f"🚀 Spawn mode: {config.config['app'].get('spawn_mode', True)}")
            
            # Show targets
            if config.config.get('targets'):
                print(f"\n🎯 Targets ({len(config.config['targets'])}):")
                for i, target in enumerate(config.config['targets'], 1):
                    print(f"   {i}. {target['class_name']}")
                    print(f"      Methods: {', '.join(target['methods'][:3])}")
                    if len(target['methods']) > 3:
                        print(f"      ... and {len(target['methods']) - 3} more")
            
            # Show global rules
            rules = config.config.get('global_rules', {})
            if rules.get('return_overrides'):
                print(f"\n🔄 Return overrides ({len(rules['return_overrides'])}):")
                for pattern, rule in list(rules['return_overrides'].items())[:3]:
                    print(f"   - {pattern} -> {rule['return_value']} ({rule['value_type']})")
                if len(rules['return_overrides']) > 3:
                    print(f"   ... and {len(rules['return_overrides']) - 3} more")
            
            if rules.get('input_modifications'):
                print(f"\n📝 Input modifications ({len(rules['input_modifications'])}):")
                for pattern, rule in list(rules['input_modifications'].items())[:3]:
                    print(f"   - {pattern}[{rule['param_index']}] = {rule['new_value']}")
                if len(rules['input_modifications']) > 3:
                    print(f"   ... and {len(rules['input_modifications']) - 3} more")
            
            # Show JavaScript scripts
            if config.config.get('custom_javascript'):
                print(f"\n📜 Custom JavaScript ({len(config.config['custom_javascript'])}):")
                for name, info in config.config['custom_javascript'].items():
                    status = "🟢" if info.get('enabled', True) else "🔴"
                    print(f"   {status} {name}: {info.get('description', 'No description')}")
                    code_preview = info.get('code', '')[:100].replace('\n', ' ')
                    if len(code_preview) >= 100:
                        code_preview += "..."
                    print(f"      Code: {code_preview}")
            
            if config.config.get('startup_scripts'):
                print(f"\n🚀 Startup scripts ({len(config.config['startup_scripts'])}):")
                for script in config.config['startup_scripts']:
                    print(f"   - {script.get('name', 'Unnamed')}: {script.get('description', 'No description')}")
            
        except Exception as e:
            print(f"[-] Error reading config: {e}")
    
    else:
        print(f"[-] Unknown command: {command}")

# Real-world usage examples with JavaScript
def banking_app_bypass_example():
    """Example configuration for banking app security bypass with JavaScript"""
    config = {
        "app": {
            "package_name": "com.bank.mobileapp",
            "spawn_mode": True
        },
        "targets": [
            {
                "class_name": "com.bank.security.AuthenticationManager",
                "methods": [".*"],
                "enabled": True
            },
            {
                "class_name": "com.bank.security.BiometricAuth",
                "methods": [".*"],
                "enabled": True
            },
            {
                "class_name": "com.bank.security.PinValidator",
                "methods": [".*"],
                "enabled": True
            }
        ],
        "global_rules": {
            "return_overrides": {
                ".*authenticate.*": {"return_value": True, "value_type": "boolean"},
                ".*validatePin.*": {"return_value": True, "value_type": "boolean"},
                ".*checkBiometric.*": {"return_value": True, "value_type": "boolean"},
                ".*isDeviceSecure.*": {"return_value": True, "value_type": "boolean"},
                ".*getRootStatus.*": {"return_value": False, "value_type": "boolean"}
            },
            "input_modifications": {
                ".*setTransactionAmount.*": {"param_index": 0, "new_value": "0.01", "value_type": "double"},
                ".*setAccountNumber.*": {"param_index": 0, "new_value": "INTERCEPTED", "value_type": "string"}
            },
            "method_logging": [
                ".*auth.*", ".*pin.*", ".*biometric.*", ".*transaction.*", 
                ".*balance.*", ".*transfer.*", ".*security.*"
            ]
        },
        "custom_javascript": {
            "ssl_pinning_bypass": {
                "description": "Comprehensive SSL Pinning Bypass",
                "enabled": True,
                "code": "Java.perform(function() { console.log('[+] Loading SSL Pinning Bypass...'); try { var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager'); var SSLContext = Java.use('javax.net.ssl.SSLContext'); var TrustManager = Java.registerClass({ name: 'com.frida.TrustManager', implements: [X509TrustManager], methods: { checkClientTrusted: function(chain, authType) {}, checkServerTrusted: function(chain, authType) {}, getAcceptedIssuers: function() { return []; } } }); var trustManager = TrustManager.$new(); var sslContext = SSLContext.getInstance('TLS'); sslContext.init(null, [trustManager], null); SSLContext.setDefault(sslContext); console.log('[+] SSL Pinning bypassed'); } catch (e) { console.log('[-] SSL bypass failed: ' + e.message); } });"
            },
            "root_detection_bypass": {
                "description": "Root Detection Bypass",
                "enabled": True,
                "code": "Java.perform(function() { try { var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer'); RootBeer.isRooted.implementation = function() { console.log('[+] Root check bypassed'); return false; }; } catch (e) {} try { var Runtime = Java.use('java.lang.Runtime'); Runtime.exec.overload('java.lang.String').implementation = function(cmd) { if (cmd.includes('su') || cmd.includes('busybox')) { console.log('[+] Blocked root command: ' + cmd); throw new Error('Command not found'); } return this.exec(cmd); }; } catch (e) {} console.log('[+] Root detection bypass loaded'); });"
            },
            "certificate_transparency_bypass": {
                "description": "Certificate Transparency Bypass",
                "enabled": True,
                "code": "Java.perform(function() { try { var CertificateTransparencyPolicy = Java.use('android.security.net.config.CertificateTransparencyPolicy'); CertificateTransparencyPolicy.isCertificateTransparencyVerificationRequired.implementation = function(hostname) { console.log('[+] CT verification bypassed for: ' + hostname); return false; }; } catch (e) {} console.log('[+] Certificate Transparency bypass loaded'); });"
            }
        }
    }
    
    with open("banking_bypass_config.json", 'w') as f:
        json.dump(config, f, indent=2)
    print("[+] Banking app bypass configuration saved to banking_bypass_config.json")

def social_media_privacy_example():
    """Example configuration for social media privacy testing"""
    config = {
        "app": {
            "package_name": "com.social.app",
            "spawn_mode": True
        },
        "targets": [
            {
                "class_name": "com.social.privacy.LocationManager",
                "methods": [".*"],
                "enabled": True
            },
            {
                "class_name": "com.social.privacy.ContactsAccess",
                "methods": [".*"],
                "enabled": True
            },
            {
                "class_name": "com.social.analytics.DataCollector",
                "methods": [".*"],
                "enabled": True
            }
        ],
        "global_rules": {
            "return_overrides": {
                ".*getLocation.*": {"return_value": None, "value_type": "null"},
                ".*getContacts.*": {"return_value": "[]", "value_type": "string"},
                ".*hasLocationPermission.*": {"return_value": False, "value_type": "boolean"},
                ".*hasContactsPermission.*": {"return_value": False, "value_type": "boolean"}
            },
            "method_blocks": [
                ".*sendAnalytics.*", ".*trackUser.*", ".*collectData.*"
            ],
            "method_logging": [
                ".*location.*", ".*contact.*", ".*permission.*", ".*analytics.*", ".*track.*"
            ]
        }
    }
    
    with open("privacy_test_config.json", 'w') as f:
        json.dump(config, f, indent=2)
    print("[+] Social media privacy test configuration saved to privacy_test_config.json")

if __name__ == "__main__":
    main()