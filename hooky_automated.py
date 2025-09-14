#!/usr/bin/env python3
"""
Automated Frida Hooking with Automation and Batch Processing
"""

import frida
import json
import time
import re
from datetime import datetime
import threading
import queue

class AutomatedFridaHook:
    """Automated hooking with predefined rules"""
    
    def __init__(self, package_name, target_class):
        self.package_name = package_name
        self.target_class = target_class
        self.device = None
        self.session = None
        self.script = None
        self.rules = {
            'input_rules': {},      # method_name: {param_index: new_value}
            'return_rules': {},     # method_name: return_value
            'log_rules': set(),     # methods to log
            'block_rules': set()    # methods to block
        }
    
    def add_input_rule(self, method_name, param_index, new_value, value_type='string'):
        """Add automatic input modification rule"""
        if method_name not in self.rules['input_rules']:
            self.rules['input_rules'][method_name] = {}
        self.rules['input_rules'][method_name][param_index] = {
            'value': new_value,
            'type': value_type
        }
        print(f"[RULE] Added input rule: {method_name}[{param_index}] = {new_value}")
    
    def add_return_rule(self, method_name, return_value, value_type='string'):
        """Add automatic return value override rule"""
        self.rules['return_rules'][method_name] = {
            'value': return_value,
            'type': value_type
        }
        print(f"[RULE] Added return rule: {method_name} -> {return_value}")
    
    def add_log_rule(self, method_pattern):
        """Add method logging rule (supports regex)"""
        self.rules['log_rules'].add(method_pattern)
        print(f"[RULE] Added log rule: {method_pattern}")
    
    def add_block_rule(self, method_name):
        """Add method blocking rule"""
        self.rules['block_rules'].add(method_name)
        print(f"[RULE] Added block rule: {method_name}")
    
    def get_automated_script(self):
        """Generate JavaScript with automated rules"""
        rules_json = json.dumps(self.rules)
        
        return f"""
        Java.perform(function() {{
            console.log("[+] Starting Automated Hook");
            
            const TARGET_CLASS = '{self.target_class}';
            const rules = {rules_json};
            
            try {{
                const targetClass = Java.use(TARGET_CLASS);
                const methods = targetClass.class.getDeclaredMethods();
                
                console.log("[+] Found " + methods.length + " methods");
                
                methods.forEach(function(method) {{
                    const methodName = method.getName();
                    if (methodName.includes('<init>') || methodName.includes('<clinit>')) return;
                    
                    try {{
                        const paramTypes = method.getParameterTypes();
                        const paramNames = [];
                        for (let i = 0; i < paramTypes.length; i++) {{
                            paramNames.push(paramTypes[i].getName());
                        }}
                        
                        const originalMethod = targetClass[methodName].overload.apply(targetClass[methodName], paramNames);
                        
                        targetClass[methodName].overload.apply(targetClass[methodName], paramNames).implementation = function() {{
                            const args = Array.prototype.slice.call(arguments);
                            
                            // Check if method should be blocked
                            if (rules.block_rules.includes(methodName)) {{
                                console.log("[BLOCKED] " + methodName);
                                return null;
                            }}
                            
                            // Check logging rules
                            let shouldLog = false;
                            rules.log_rules.forEach(function(pattern) {{
                                if (methodName.match(pattern)) {{
                                    shouldLog = true;
                                }}
                            }});
                            
                            if (shouldLog) {{
                                console.log("[LOG] " + methodName + " called");
                                for (let i = 0; i < args.length; i++) {{
                                    console.log("  [" + i + "] " + args[i]);
                                }}
                            }}
                            
                            // Apply input modification rules
                            if (rules.input_rules[methodName]) {{
                                Object.keys(rules.input_rules[methodName]).forEach(function(paramIndex) {{
                                    const rule = rules.input_rules[methodName][paramIndex];
                                    const oldValue = args[paramIndex];
                                    
                                    if (rule.type === 'string') {{
                                        args[paramIndex] = rule.value;
                                    }} else if (rule.type === 'int') {{
                                        args[paramIndex] = parseInt(rule.value);
                                    }} else if (rule.type === 'boolean') {{
                                        args[paramIndex] = rule.value;
                                    }} else if (rule.type === 'double') {{
                                        args[paramIndex] = parseFloat(rule.value);
                                    }}
                                    
                                    console.log("[AUTO-MOD] " + methodName + "[" + paramIndex + "] " + oldValue + " -> " + args[paramIndex]);
                                }});
                            }}
                            
                            // Call original method
                            let result;
                            if (rules.return_rules[methodName]) {{
                                // Skip calling original if return is overridden
                                const returnRule = rules.return_rules[methodName];
                                if (returnRule.type === 'string') {{
                                    result = returnRule.value;
                                }} else if (returnRule.type === 'int') {{
                                    result = parseInt(returnRule.value);
                                }} else if (returnRule.type === 'boolean') {{
                                    result = returnRule.value;
                                }} else if (returnRule.type === 'null') {{
                                    result = null;
                                }} else {{
                                    result = returnRule.value;
                                }}
                                console.log("[AUTO-RET] " + methodName + " -> " + result);
                            }} else {{
                                result = originalMethod.apply(this, args);
                            }}
                            
                            return result;
                        }};
                        
                        console.log("[+] Hooked: " + methodName);
                        
                    }} catch (e) {{
                        console.log("[-] Failed to hook: " + methodName + " - " + e);
                    }}
                }});
                
            }} catch (e) {{
                console.log("[-] Error: " + e);
            }}
        }});
        """
    
    def start_automated(self):
        """Start automated hooking"""
        try:
            self.device = frida.get_usb_device()
            
            try:
                self.session = self.device.attach(self.package_name)
                print("[+] Attached to running process")
            except:
                pid = self.device.spawn([self.package_name])
                self.session = self.device.attach(pid)
                self.device.resume(pid)
                print("[+] Spawned new process")
            
            self.script = self.session.create_script(self.get_automated_script())
            self.script.on('message', lambda msg, data: print(f"[JS] {msg}") if msg['type'] == 'send' else print(f"[ERROR] {msg}"))
            self.script.load()
            
            print("[+] Automated hooking active")
            
        except Exception as e:
            print(f"[-] Error: {e}")

class BatchHooker:
    """Hook multiple classes/methods in batch"""
    
    def __init__(self, package_name):
        self.package_name = package_name
        self.targets = []  # List of (class_name, method_patterns)
        
    def add_target(self, class_name, method_patterns=None):
        """Add a class to hook"""
        if method_patterns is None:
            method_patterns = [".*"]  # All methods
        self.targets.append((class_name, method_patterns))
        
    def generate_batch_script(self):
        """Generate script to hook multiple targets"""
        targets_js = "["
        for class_name, patterns in self.targets:
            patterns_str = '["' + '","'.join(patterns) + '"]'
            targets_js += f'{{"class":"{class_name}","patterns":{patterns_str}}},'
        targets_js = targets_js.rstrip(',') + "]"
        
        return f"""
        Java.perform(function() {{
            const targets = {targets_js};
            
            targets.forEach(function(target) {{
                try {{
                    const targetClass = Java.use(target.class);
                    console.log("[+] Hooking class: " + target.class);
                    
                    const methods = targetClass.class.getDeclaredMethods();
                    
                    methods.forEach(function(method) {{
                        const methodName = method.getName();
                        if (methodName.includes('<init>') || methodName.includes('<clinit>')) return;
                        
                        // Check if method matches any pattern
                        let shouldHook = false;
                        target.patterns.forEach(function(pattern) {{
                            if (methodName.match(pattern)) {{
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
                            
                            targetClass[methodName].overload.apply(targetClass[methodName], paramNames).implementation = function() {{
                                console.log("[BATCH] " + target.class + "." + methodName);
                                
                                const result = this[methodName].apply(this, arguments);
                                return result;
                            }};
                            
                            console.log("[+] Hooked: " + target.class + "." + methodName);
                            
                        }} catch (e) {{
                            console.log("[-] Failed to hook: " + methodName);
                        }}
                    }});
                    
                }} catch (e) {{
                    console.log("[-] Class not found: " + target.class);
                }}
            }});
        }});
        """

class FridaRecorder:
    """Record and replay method calls"""
    
    def __init__(self, package_name, target_class):
        self.package_name = package_name
        self.target_class = target_class
        self.recorded_calls = []
        self.recording = False
        
    def start_recording(self):
        """Start recording method calls"""
        self.recording = True
        self.recorded_calls = []
        
        device = frida.get_usb_device()
        
        try:
            session = device.attach(self.package_name)
        except:
            pid = device.spawn([self.package_name])
            session = device.attach(pid)
            device.resume(pid)
        
        record_script = f"""
        Java.perform(function() {{
            const targetClass = Java.use('{self.target_class}');
            const methods = targetClass.class.getDeclaredMethods();
            
            methods.forEach(function(method) {{
                const methodName = method.getName();
                if (methodName.includes('<init>') || methodName.includes('<clinit>')) return;
                
                try {{
                    const paramTypes = method.getParameterTypes();
                    const paramNames = [];
                    for (let i = 0; i < paramTypes.length; i++) {{
                        paramNames.push(paramTypes[i].getName());
                    }}
                    
                    targetClass[methodName].overload.apply(targetClass[methodName], paramNames).implementation = function() {{
                        const args = Array.prototype.slice.call(arguments);
                        
                        // Record the call
                        send({{
                            type: 'record',
                            timestamp: Date.now(),
                            method: methodName,
                            class: '{self.target_class}',
                            arguments: args.map((arg, i) => ({{
                                index: i,
                                type: paramNames[i],
                                value: String(arg)
                            }}))
                        }});
                        
                        const result = this[methodName].apply(this, arguments);
                        
                        // Record the result
                        send({{
                            type: 'result',
                            method: methodName,
                            return_value: String(result),
                            timestamp: Date.now()
                        }});
                        
                        return result;
                    }};
                    
                }} catch (e) {{
                    console.log("Failed to hook: " + methodName);
                }}
            }});
        }});
        """
        
        script = session.create_script(record_script)
        
        def on_message(message, data):
            if message['type'] == 'send':
                payload = message['payload']
                self.recorded_calls.append(payload)
                if payload['type'] == 'record':
                    print(f"[RECORDED] {payload['class']}.{payload['method']}")
        
        script.on('message', on_message)
        script.load()
        
        print("[+] Recording started. Press Enter to stop...")
        input()
        
        self.recording = False
        script.unload()
        session.detach()
        
        print(f"[+] Recorded {len(self.recorded_calls)} calls")
        
    def save_recording(self, filename):
        """Save recorded calls to file"""
        with open(filename, 'w') as f:
            json.dump(self.recorded_calls, f, indent=2)
        print(f"[+] Recording saved to {filename}")
        
    def load_recording(self, filename):
        """Load recorded calls from file"""
        with open(filename, 'r') as f:
            self.recorded_calls = json.load(f)
        print(f"[+] Loaded {len(self.recorded_calls)} calls from {filename}")

# Usage examples
def example_automated_auth_bypass():
    """Example: Automated authentication bypass"""
    hook = AutomatedFridaHook("com.example.app", "com.example.AuthManager")
    
    # Set up automatic rules
    hook.add_return_rule("authenticate", True, "boolean")
    hook.add_return_rule("checkPassword", True, "boolean")
    hook.add_return_rule("isValidUser", True, "boolean")
    hook.add_input_rule("setUsername", 0, "admin", "string")
    hook.add_log_rule(".*auth.*")  # Log all methods containing "auth"
    
    hook.start_automated()
    
    try:
        input("Press Enter to stop...")
    except KeyboardInterrupt:
        pass

def example_batch_hooking():
    """Example: Hook multiple security-related classes"""
    batch = BatchHooker("com.example.app")
    
    # Add multiple targets
    batch.add_target("com.example.AuthManager", ["authenticate", "login.*"])
    batch.add_target("com.example.CryptoManager", ["encrypt.*", "decrypt.*"])
    batch.add_target("com.example.NetworkManager", [".*request.*"])
    
    device = frida.get_usb_device()
    session = device.attach("com.example.app")
    
    script = session.create_script(batch.generate_batch_script())
    script.on('message', lambda msg, data: print(f"[BATCH] {msg}"))
    script.load()
    
    print("[+] Batch hooking active")
    input("Press Enter to stop...")

def example_recording_session():
    """Example: Record method calls for analysis"""
    recorder = FridaRecorder("com.example.app", "com.example.DataManager")
    
    print("[+] Starting recording session...")
    recorder.start_recording()
    
    # Save the recording
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"recorded_calls_{timestamp}.json"
    recorder.save_recording(filename)
    
    # Analyze the recording
    print(f"[+] Analysis of {len(recorder.recorded_calls)} calls:")
    method_counts = {}
    for call in recorder.recorded_calls:
        if call['type'] == 'record':
            method = call['method']
            method_counts[method] = method_counts.get(method, 0) + 1
    
    for method, count in sorted(method_counts.items()):
        print(f"  {method}: {count} calls")

if __name__ == "__main__":
    print("Advanced Frida Examples")
    print("1. Automated auth bypass")
    print("2. Batch hooking")  
    print("3. Recording session")
    
    choice = input("Select example (1-3): ")
    
    if choice == '1':
        example_automated_auth_bypass()
    elif choice == '2':
        example_batch_hooking()
    elif choice == '3':
        example_recording_session()
    else:
        print("Invalid choice")