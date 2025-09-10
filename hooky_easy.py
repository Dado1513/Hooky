#!/usr/bin/env python3
"""
Frida Interactive Method Interceptor - Frida Easy Hooking
"""

import frida
import sys
import json
import time
import re
from threading import Thread, Event

# Quick setup script for common use cases
class QuickFridaHook:
    def __init__(self, app_name=None, class_name=None):
        self.app_name = app_name
        self.class_name = class_name  # Fixed: ensure this is properly set
        self.session = None
        self.script = None
        
    def simple_hook(self, method_patterns=None):
        """Simple hook with basic user interaction and regex method filtering"""
        if not method_patterns:
            method_patterns = [".*"]  # Hook all methods by default
            
        # Convert method patterns to a JavaScript array string
        js_patterns = json.dumps(method_patterns)
        
        # Ensure class_name is a string, not a method reference
        if callable(self.class_name) and str(self.class_name).startswith('<built-in method'):
            # This means someone passed class_name.strip instead of class_name.strip()
            raise ValueError("class_name appears to be a method reference. Use .strip() not .strip")
        
        class_name = str(self.class_name).strip() if self.class_name else ""
        if not class_name:
            raise ValueError("class_name cannot be empty")
            
        js_code = f"""
        // Sleep function for synchronous delays
        function sleep(ms) {{
            var start = new Date().getTime();
            while (new Date().getTime() < start + ms) {{
                // Busy wait
            }}
        }}
        
        // Method pattern matching function
        function matchesMethodPattern(methodName, patterns) {{
            for (let i = 0; i < patterns.length; i++) {{
                try {{
                    const regex = new RegExp(patterns[i], 'i'); // Case insensitive
                    if (regex.test(methodName)) {{
                        return true;
                    }}
                }} catch (e) {{
                    console.log('[-] Invalid regex pattern: ' + patterns[i]);
                }}
            }}
            return false;
        }}
        
        // Validate class name on JavaScript side
        function validateClassName(className) {{
            if (!className || typeof className !== 'string') {{
                throw new Error('Invalid class name: ' + className);
            }}
            if (className.includes('<built-in')) {{
                throw new Error('PYTHON ERROR: You passed a Python method reference. Add () after .strip in your Python code!');
            }}
            if (className.trim() === '') {{
                throw new Error('Class name is empty or whitespace');
            }}
            return className.trim();
        }}
        
        // Retry mechanism for class loading
        function tryFindClass(className, maxRetries, delay) {{
            className = validateClassName(className);
            console.log('[DEBUG] Attempting to find class: "' + className + '"');
            
            var retries = 0;
            
            function attempt() {{
                try {{
                    var clazz = Java.use(className);
                    console.log("[+] Class found: " + className);
                    return clazz;
                }} catch (e) {{
                    retries++;
                    console.log("[-] Attempt " + retries + " failed: " + e.message);
                    
                    if (retries < maxRetries) {{
                        console.log("[-] Retrying in " + delay + "ms...");
                        sleep(delay);
                        return attempt();
                    }} else {{
                        console.log("[-] Failed to find class after " + maxRetries + " attempts");
                        throw e;
                    }}
                }}
            }}
            
            return attempt();
        }}
        
        Java.perform(function() {{
            // Wait for app initialization
            setTimeout(function() {{
                console.log("[*] Starting class hooking after delay...");
                console.log("[DEBUG] Target class name: '{class_name}'");
                
                // Method patterns from Python
                const methodPatterns = {js_patterns};
                console.log("[DEBUG] Method patterns: " + JSON.stringify(methodPatterns));
                
                try {{
                    // Validate and find the class with retries
                    const targetClass = tryFindClass('{class_name}', 5, 1000);
                    
                    // Additional delay before method enumeration
                    sleep(500);
                    
                    const methods = targetClass.class.getDeclaredMethods();
                    console.log('[+] Found ' + methods.length + ' methods in {class_name}');   
                    
                    const originalMethods = {{}};  // Store original implementations
                    let hookedCount = 0;
                    
                    methods.forEach(function(method) {{
                        const methodName = method.getName();
                        if (methodName.includes('<init>') || methodName.includes('<clinit>')) return;
                        
                        // Check if method matches any of the patterns
                        if (!matchesMethodPattern(methodName, methodPatterns)) {{
                            console.log('[SKIP] Method does not match patterns: ' + methodName);
                            return;
                        }}
                        
                        try {{
                            const paramTypes = method.getParameterTypes();
                            const paramNames = [];
                            for (let i = 0; i < paramTypes.length; i++) {{
                                paramNames.push(paramTypes[i].getName());
                            }}
                            
                            // Store original implementation
                            const methodKey = methodName + '_' + paramNames.join('_');
                            
                            // Add small delay before hooking each method
                            sleep(50);
                            
                            originalMethods[methodKey] = targetClass[methodName].overload.apply(targetClass[methodName], paramNames);
                            
                            targetClass[methodName].overload.apply(targetClass[methodName], paramNames).implementation = function() {{
                                console.log('\\n=== METHOD CALL ===');
                                console.log('Class: {class_name}');
                                console.log('Method: ' + methodName);
                                console.log('Arguments:');
                                
                                const args = Array.prototype.slice.call(arguments);
                                for (let i = 0; i < args.length; i++) {{
                                    try {{
                                        console.log('  [' + i + '] ' + paramNames[i] + ': ' + args[i]);
                                    }} catch (e) {{
                                        console.log('  [' + i + '] ' + paramNames[i] + ': [Error displaying value]');
                                    }}
                                }}
                                
                                // Call original method using stored reference
                                let result;
                                try {{
                                    result = originalMethods[methodKey].apply(this, arguments);
                                    console.log('Return Type ['+methodName+']: ' + (result === null ? 'null' : typeof result));
                                    console.log('Return Value ['+methodName+']: ' + result);
                                }} catch (e) {{
                                    console.log('Error calling original method: ' + e);
                                    throw e;
                                }}
                                
                                console.log('===================\\n');
                                return result;
                            }};
                            
                            hookedCount++;
                            console.log('[+] Hooked: ' + methodName + ' (params: ' + paramNames.length + ')');
                        }} catch (e) {{
                            console.log('[-] Failed to hook: ' + methodName + ' - ' + e);
                        }}
                    }});
                    
                    console.log("[+] Hooking completed successfully!");
                    console.log("[+] Successfully hooked " + hookedCount + " methods");
                    
                }} catch (e) {{
                    console.log("[-] Failed to initialize hooks: " + e);
                    console.log("[-] Error details: " + e.message);
                    console.log("[-] Stack trace: " + e.stack);
                    
                    // List available classes for debugging
                    console.log("[*] Listing loaded classes containing similar names...");
                    Java.enumerateLoadedClasses({{
                        onMatch: function(className) {{
                            if (className.toLowerCase().includes('{class_name}'.toLowerCase().split('.').pop())) {{
                                console.log("[DEBUG] Similar class found: " + className);
                            }}
                        }},
                        onComplete: function() {{
                            console.log("[DEBUG] Class enumeration complete");
                        }}
                    }});
                }}
            }}, 3000); // Initial 3-second delay for app startup
        }});
        """
        return js_code


# Interactive CLI helper
class FridaCLI:
    def __init__(self):
        self.hooks = {}
        self.current_session = None
        
    def show_menu(self):
        print("\n" + "="*50)
        print("FRIDA INTERACTIVE MENU")
        print("="*50)
        print("1. List running processes")
        print("2. Hook specific class")
        print("3. Custom JavaScript")
        print("4. Show active hooks")
        print("5. Exit")
        print("="*50)
        
    def list_processes(self):
        """List running processes"""
        try:
            device = frida.get_usb_device()
            processes = device.enumerate_processes()
            print(f"\n{'PID':<8} {'Name':<30} {'Identifier'}")
            print("-" * 60)
            for p in processes:
                print(f"{p.pid:<8} {p.name:<30} {getattr(p, 'identifier', 'N/A')}")
        except Exception as e:
            print(f"Error listing processes: {e}")
    
    def hook_class(self):
        """Interactive class hooking with regex method filtering"""
        app_name = input("Enter app package name: ").strip()
        class_name = input("Enter class name: ").strip()
        
        # Get method filtering patterns
        print("\nMethod filtering options:")
        print("1. Hook all methods (default)")
        print("2. Hook specific method name")
        print("3. Use regex patterns")
        filter_choice = input("Choose option (1-3): ").strip() or "1"
        
        method_patterns = [".*"]  # Default: all methods
        
        if filter_choice == "2":
            method_name = input("Enter method name: ").strip()
            method_patterns = [f"^{re.escape(method_name)}$"]
        elif filter_choice == "3":
            patterns_input = input("Enter regex patterns (comma separated): ").strip()
            if patterns_input:
                method_patterns = [p.strip() for p in patterns_input.split(",")]
        
        print(f"[INFO] Method patterns: {method_patterns}")
        
        try:
            device = frida.get_usb_device()
            
            # Try to find the app
            try:
                # Try attach first
                session = device.attach(app_name)
                print("[+] Attached to running process")
            except:
                # Spawn if not running
                pid = device.spawn([app_name])
                session = device.attach(pid)
                device.resume(pid)
                print("[+] Spawned new process")
                    
            # Create interactive hook
            hook = QuickFridaHook(app_name, class_name)
            js_code = hook.simple_hook(method_patterns)
            script = session.create_script(js_code)
            
            def on_message(message, data):
                if message['type'] == 'send':
                    payload = message['payload']
                    print(f"[JS] {payload}")
                elif message['type'] == 'error':
                    print(f"[JS ERROR] {message['description']}")
            
            script.on('message', on_message)
            script.load()
            
            self.current_session = session
            self.hooks[class_name] = script
            
            print(f"[+] Hooking {class_name} with patterns {method_patterns}")
            print("Press Ctrl+C to stop...")
            try:
                sys.stdin.read()
            except KeyboardInterrupt:
                print("\n[*] Stopping...")
            
        except Exception as e:
            print(f"Error: {e}")
    
    def run(self):
        """Run the interactive CLI"""
        while True:
            self.show_menu()
            choice = input("Select option (1-5): ").strip()
            
            if choice == '1':
                self.list_processes()
            elif choice == '2':
                self.hook_class()
            elif choice == '3':
                print("Custom JavaScript - coming soon")
            elif choice == '4':
                print(f"Active hooks: {list(self.hooks.keys())}")
            elif choice == '5':
                print("Goodbye!")
                break
            else:
                print("Invalid option")
            
            input("\nPress Enter to continue...")

# Utility functions
def quick_start(package_name, class_name, method_patterns=None):
    """Quick start function for common use case with regex support"""
    print(f"Quick starting hook for {package_name} -> {class_name}")
    
    if method_patterns is None:
        method_patterns = [".*"]
    
    
    device = frida.get_usb_device()
    pid = device.spawn([package_name])
    session = device.attach(pid)
    print("[+] Spawned new process, attaching hooks before app resume...")

    delay_before_resume = 5  # seconds
    
    # Convert patterns to JavaScript regex
    js_patterns = json.dumps(method_patterns)
    
    js_code = f"""
    Java.perform(function() {{
        function matchesPattern(methodName, patterns) {{
            for (let i = 0; i < patterns.length; i++) {{
                try {{
                    const regex = new RegExp(patterns[i], 'i');
                    if (regex.test(methodName)) return true;
                }} catch (e) {{
                    console.log('Invalid regex: ' + patterns[i]);
                }}
            }}
            return false;
        }}
        
        setTimeout(function() {{
            try {{
                const targetClass = Java.use('{class_name}');
                console.log('[+] Found target class: {class_name}');
                
                const methods = targetClass.class.getDeclaredMethods();
                console.log('[+] Found ' + methods.length + ' methods');
                
                const patterns = {js_patterns};
                let hookedCount = 0;
                
                methods.forEach(function(method) {{
                    const methodName = method.getName();
                    if (methodName.includes('<init>')) return;
                    
                    if (!matchesPattern(methodName, patterns)) {{
                        return; // Skip methods that don't match
                    }}
                    
                    try {{
                        console.log('[+] Hooking: ' + methodName);
                        
                        // Get parameter types for overloading
                        const paramTypes = method.getParameterTypes();
                        const paramNames = [];
                        for (let i = 0; i < paramTypes.length; i++) {{
                            paramNames.push(paramTypes[i].getName());
                        }}
                        
                        // Hook with proper overloading
                        const originalMethod = targetClass[methodName].overload.apply(targetClass[methodName], paramNames);
                        
                        targetClass[methodName].overload.apply(targetClass[methodName], paramNames).implementation = function() {{
                            console.log('\\n>>> Called: ' + methodName);
                            console.log('>>> Class: {class_name}');
                            console.log('>>> Arguments (' + arguments.length + '):');
                            
                            for (let i = 0; i < arguments.length; i++) {{
                                console.log('    [' + i + '] ' + paramNames[i] + ': ' + arguments[i]);
                            }}
                            
                            // Call original
                            const result = originalMethod.apply(this, arguments);
                            console.log('>>> Return Type ['+methodName+']: ' + (result === null ? 'null' : typeof result));
                            console.log('>>> Return Value ['+methodName+']: ' + result);
                            console.log('<<<');
                            
                            return result;
                        }};
                        
                        hookedCount++;
                    }} catch (e) {{
                        console.log('[-] Could not hook: ' + methodName + ' - ' + e);
                    }}
                }});
                
                console.log('[+] Successfully hooked ' + hookedCount + ' methods');
            }} catch (e) {{
                console.log('[-] Error: ' + e);
            }}
        }}, 2000);
    }});
    """
    
    
    script = session.create_script(js_code)
    script.on('message', lambda msg, data: print(f"[JS] {msg}"))
    script.load()

    print(f"[+] Hooks installed. Sleeping {delay_before_resume}s before resuming app...")
    time.sleep(delay_before_resume)
    device.resume(pid)

    print("[+] Script loaded. Monitoring...")
    print(f"[+] Method patterns: {method_patterns}")
    try:
        input("Press Enter to stop...")
    except KeyboardInterrupt:
        pass
    
    session.detach()

if __name__ == "__main__":
    if len(sys.argv) >= 3:
        # Quick start mode with optional regex patterns
        package = sys.argv[1]
        class_name = sys.argv[2]
        patterns = sys.argv[3:] if len(sys.argv) > 3 else None
        quick_start(package, class_name, patterns)
    elif len(sys.argv) == 2 and sys.argv[1] == "--cli":
        # Interactive CLI mode
        cli = FridaCLI()
        cli.run()
    else:
        print("Usage:")
        print(f"  {sys.argv[0]} <package> <class> [regex_patterns...]     # Quick hook")
        print(f"  {sys.argv[0]} --cli                                     # Interactive CLI")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} com.example.app com.example.AuthManager")
        print(f"  {sys.argv[0]} com.example.app com.example.AuthManager 'login.*' 'auth.*'")
        print(f"  {sys.argv[0]} --cli")