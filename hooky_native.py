#!/usr/bin/env python3
"""
Native Method Hooker using Frida
Hooks native methods in a shared library based on regex patterns
Enhanced with dedicated function discovery mode
"""

import frida
import sys
import re
import argparse
import time
from typing import List, Optional

class NativeMethodHooker:
    def __init__(self, target, library_path: str, pattern: str, device_id: Optional[str] = None):
        self.target = target
        self.library_path = library_path
        self.pattern = re.compile(pattern) if pattern else None
        self.device_id = device_id
        
        # Determine if we should spawn or attach based on target type
        if isinstance(target, int) or (isinstance(target, str) and target.isdigit()):
            self.target = int(target) if isinstance(target, str) else target
            self.should_spawn = False
            print(f"[+] Target is PID {self.target} - will attach to existing process")
        else:
            self.should_spawn = True
            print(f"[+] Target is package '{target}' - will spawn new process")
        
        self.device = None
        self.session = None
        self.script = None
        
    def get_device(self):
        """Get the appropriate Frida device"""
        if self.device:
            return self.device
            
        try:
            if self.device_id:
                self.device = frida.get_device(self.device_id)
                print(f"[+] Using device: {self.device.name} ({self.device_id})")
            else:
                # For mobile apps, we typically want USB device
                devices = frida.enumerate_devices()
                usb_devices = [d for d in devices if d.type == 'usb']
                
                if usb_devices:
                    self.device = usb_devices[0]  # Use first USB device
                    print(f"[+] Auto-selected USB device: {self.device.name}")
                else:
                    self.device = frida.get_local_device()
                    print(f"[+] No USB devices found, using local device")
                    
            return self.device
        except Exception as e:
            print(f"[-] Error getting device: {e}")
            raise

    def discover_all_functions(self) -> List[dict]:
        """Discover ALL functions in the specified library"""
        print(f"[+] Discovering all functions in library: {self.library_path}")
        
        # Script to enumerate all exports in the library
        enum_script = f"""
        var lib_base = Module.findBaseAddress("{self.library_path}");
        if (!lib_base) {{
            console.log("[-] Library {self.library_path} not loaded");
            send({{"type": "error", "message": "Library not found"}});
        }} else {{
            console.log("[+] Library base address: " + lib_base);
            
            try {{
                var exports = Module.enumerateExportsSync("{self.library_path}");
                var functions = [];
                var variables = [];
                
                exports.forEach(function(exp) {{
                    if (exp.type === "function") {{
                        functions.push({{
                            name: exp.name,
                            address: exp.address,
                            type: exp.type
                        }});
                    }} else if (exp.type === "variable") {{
                        variables.push({{
                            name: exp.name,
                            address: exp.address,
                            type: exp.type
                        }});
                    }}
                }});
                
                send({{"type": "functions", "data": functions}});
                send({{"type": "variables", "data": variables}});
                send({{"type": "done"}});
                
            }} catch(e) {{
                console.log("[-] Error enumerating exports: " + e);
                send({{"type": "error", "message": "Failed to enumerate exports: " + e}});
            }}
        }}
        """
        
        functions = []
        variables = []
        
        def on_message(message, data):
            nonlocal functions, variables
            if message['type'] == 'send':
                payload = message['payload']
                if payload['type'] == 'functions':
                    functions = payload['data']
                elif payload['type'] == 'variables':
                    variables = payload['data']
                elif payload['type'] == 'error':
                    print(f"[-] {payload['message']}")
        
        try:
            script = self.session.create_script(enum_script)
            script.on('message', on_message)
            script.load()
            
            # Wait for enumeration to complete
            time.sleep(3)
            
            script.unload()
            
            # Print results
            print(f"\n[+] Library Analysis Results for: {self.library_path}")
            print("=" * 80)
            
            if functions:
                print(f"\n[+] FUNCTIONS ({len(functions)} found):")
                print("-" * 80)
                print(f"{'Name':<50} {'Address':<12} {'Type'}")
                print("-" * 80)
                
                # Sort functions by name for better readability
                functions.sort(key=lambda f: f['name'].lower())
                
                for func in functions:
                    print(f"{func['name']:<50} {func['address']:<12} {func['type']}")
            else:
                print("\n[-] No functions found in this library")
                
            if variables:
                print(f"\n[+] EXPORTED VARIABLES ({len(variables)} found):")
                print("-" * 80)
                print(f"{'Name':<50} {'Address':<12} {'Type'}")
                print("-" * 80)
                
                # Sort variables by name for better readability
                variables.sort(key=lambda v: v['name'].lower())
                
                for var in variables:
                    print(f"{var['name']:<50} {var['address']:<12} {var['type']}")
            else:
                print("\n[-] No exported variables found in this library")
                
            return functions
            
        except Exception as e:
            print(f"[-] Error during function discovery: {e}")
            return []

    def discover_functions_with_details(self) -> List[dict]:
        """Discover functions with additional details like parameters and return types"""
        print(f"[+] Discovering functions with details in library: {self.library_path}")
        
        # Enhanced script that tries to get more information about functions
        enum_script = f"""
        var lib_base = Module.findBaseAddress("{self.library_path}");
        if (!lib_base) {{
            send({{"type": "error", "message": "Library not found"}});
        }} else {{
            try {{
                var exports = Module.enumerateExportsSync("{self.library_path}");
                var detailed_functions = [];
                
                exports.forEach(function(exp) {{
                    if (exp.type === "function") {{
                        var func_info = {{
                            name: exp.name,
                            address: exp.address,
                            type: exp.type,
                            offset: exp.address.sub(lib_base).toString(16)
                        }};
                        
                        // Try to get function signature if available
                        try {{
                            // This might work for some functions with debug info
                            var sig = DebugSymbol.fromAddress(exp.address);
                            if (sig && sig.toString() !== exp.address.toString()) {{
                                func_info.signature = sig.toString();
                            }}
                        }} catch(e) {{
                            // No debug info available
                        }}
                        
                        detailed_functions.push(func_info);
                    }}
                }});
                
                send({{"type": "detailed_functions", "data": detailed_functions}});
                send({{"type": "done"}});
                
            }} catch(e) {{
                send({{"type": "error", "message": "Failed to enumerate exports: " + e}});
            }}
        }}
        """
        
        functions = []
        
        def on_message(message, data):
            nonlocal functions
            if message['type'] == 'send':
                payload = message['payload']
                if payload['type'] == 'detailed_functions':
                    functions = payload['data']
                elif payload['type'] == 'error':
                    print(f"[-] {payload['message']}")
        
        try:
            script = self.session.create_script(enum_script)
            script.on('message', on_message)
            script.load()
            
            # Wait for enumeration to complete
            time.sleep(3)
            
            script.unload()
            
            # Print detailed results
            print(f"\n[+] Detailed Function Analysis for: {self.library_path}")
            print("=" * 100)
            
            if functions:
                print(f"\n[+] FUNCTIONS WITH DETAILS ({len(functions)} found):")
                print("-" * 100)
                print(f"{'Name':<40} {'Address':<12} {'Offset':<12} {'Signature'}")
                print("-" * 100)
                
                # Sort functions by name
                functions.sort(key=lambda f: f['name'].lower())
                
                for func in functions:
                    signature = func.get('signature', 'N/A')
                    if len(signature) > 30:
                        signature = signature[:27] + "..."
                    print(f"{func['name']:<40} {func['address']:<12} 0x{func['offset']:<10} {signature}")
            else:
                print("\n[-] No functions found in this library")
                
            return functions
            
        except Exception as e:
            print(f"[-] Error during detailed function discovery: {e}")
            return []

    def create_hook_script(self, functions: List[str]) -> str:
        """Generate Frida script to hook specified functions"""
        
        script_template = """
        var lib = Module.findExportByName("{library}", null);
        if (!lib) {{
            console.log("[-] Library {library} not found");
        }} else {{
            console.log("[+] Library {library} found at: " + lib);
        }}
        
        var hooks = [];
        
        {hook_functions}
        
        console.log("[+] Installed " + hooks.length + " hooks");
        """
        
        hook_template = """
        // Hook {func_name}
        try {{
            var {func_name}_addr = Module.findExportByName("{library}", "{func_name}");
            if ({func_name}_addr) {{
                var {func_name}_hook = Interceptor.attach({func_name}_addr, {{
                    onEnter: function(args) {{
                        console.log("[+] Called: {func_name}");
                        console.log("    Address: " + this.context.pc);
                        console.log("    Thread: " + Process.getCurrentThreadId());
                        
                        // Log arguments (adjust based on function signature)
                        for (var i = 0; i < Math.min(6, arguments.length); i++) {{
                            try {{
                                console.log("    Arg[" + i + "]: " + args[i] + " (0x" + args[i].toString(16) + ")");
                                
                                // Try to read as string if it looks like a pointer
                                if (args[i].toInt32() > 0x1000) {{
                                    try {{
                                        var str = Memory.readUtf8String(args[i]);
                                        if (str && str.length > 0 && str.length < 200) {{
                                            console.log("    Arg[" + i + "] as string: " + str);
                                        }}
                                    }} catch(e) {{
                                        // Not a valid string pointer
                                    }}
                                }}
                            }} catch(e) {{
                                console.log("    Arg[" + i + "]: <unable to read>");
                            }}
                        }}
                        
                        // Store entry time for duration calculation
                        this.start_time = Date.now();
                    }},
                    onLeave: function(retval) {{
                        var duration = Date.now() - this.start_time;
                        console.log("[+] Returning from: {func_name}");
                        console.log("    Return value: " + retval + " (0x" + retval.toString(16) + ")");
                        console.log("    Duration: " + duration + "ms");
                        
                        // Try to read return value as string if it looks like a pointer
                        if (retval.toInt32() > 0x1000) {{
                            try {{
                                var str = Memory.readUtf8String(retval);
                                if (str && str.length > 0 && str.length < 200) {{
                                    console.log("    Return as string: " + str);
                                }}
                            }} catch(e) {{
                                // Not a valid string pointer
                            }}
                        }}
                        console.log("---");
                    }}
                }});
                hooks.push({func_name}_hook);
                console.log("[+] Hooked: {func_name} at " + {func_name}_addr);
            }} else {{
                console.log("[-] Function {func_name} not found in {library}");
            }}
        }} catch(e) {{
            console.log("[-] Error hooking {func_name}: " + e);
        }}
        """
        
        hook_functions = ""
        for func in functions:
            hook_functions += hook_template.format(
                func_name=func,
                library=self.library_path
            )
        
        return script_template.format(
            library=self.library_path,
            hook_functions=hook_functions
        )
    
    def find_matching_functions(self) -> List[str]:
        """Find functions in the library that match the regex pattern"""
        
        # Script to enumerate exports and find matches
        enum_script = f"""
        var lib_base = Module.findBaseAddress("{self.library_path}");
        if (!lib_base) {{
            console.log("[-] Library {self.library_path} not loaded");
            send({{"type": "error", "message": "Library not found"}});
        }} else {{
            console.log("[+] Library base address: " + lib_base);
            
            try {{
                var exports = Module.enumerateExportsSync("{self.library_path}");
                var matches = [];
                
                exports.forEach(function(exp) {{
                    if (exp.type === "function") {{
                        send({{"type": "function", "name": exp.name, "address": exp.address}});
                    }}
                }});
                
                send({{"type": "done"}});
            }} catch(e) {{
                console.log("[-] Error enumerating exports: " + e);
                send({{"type": "error", "message": "Failed to enumerate exports"}});
            }}
        }}
        """
        
        functions = []
        
        def on_message(message, data):
            if message['type'] == 'send':
                payload = message['payload']
                if payload['type'] == 'function':
                    func_name = payload['name']
                    if self.pattern.search(func_name):
                        functions.append(func_name)
                        print(f"[+] Found matching function: {func_name} at {payload['address']}")
                elif payload['type'] == 'error':
                    print(f"[-] {payload['message']}")
        
        try:
            script = self.session.create_script(enum_script)
            script.on('message', on_message)
            script.load()
            
            # Wait for enumeration to complete
            time.sleep(2)
            
            script.unload()
            
        except Exception as e:
            print(f"[-] Error during function enumeration: {e}")
        
        return functions

    def list_processes(self):
        """List processes on the target device"""
        try:
            device = self.get_device()
            print(f"[+] Processes on device: {device.name}")
            processes = device.enumerate_processes()
            
            # Sort by name for better readability
            processes.sort(key=lambda p: p.name.lower())
            
            for process in processes:
                print(f"    PID: {process.pid:>6} | Name: {process.name}")
                
        except Exception as e:
            print(f"[-] Error listing processes: {e}")
            print("[-] Make sure the device is connected and accessible")

    def list_loaded_libraries(self):
        """List all native libraries loaded by the target process"""
        print(f"[+] Enumerating loaded libraries...")
        
        # Script to enumerate loaded modules
        enum_script = """
        try {
            var modules = Process.enumerateModules();
            var libraries = [];
            
            modules.forEach(function(module) {
                // Filter for native libraries (typically .so for Android, .dylib for iOS)
                if (module.name.endsWith('.so') || 
                    module.name.endsWith('.dylib') || 
                    module.name.includes('lib') ||
                    module.path.includes('/system/') ||
                    module.path.includes('/vendor/') ||
                    module.path.includes('/data/')) {
                    
                    libraries.push({
                        name: module.name,
                        base: module.base,
                        size: module.size,
                        path: module.path
                    });
                }
            });
            
            // Sort by name for better readability
            libraries.sort(function(a, b) {
                return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
            });
            
            send({"type": "libraries", "data": libraries});
            
        } catch(e) {
            send({"type": "error", "message": "Failed to enumerate modules: " + e});
        }
        """
        
        def on_message(message, data):
            if message['type'] == 'send':
                payload = message['payload']
                if payload['type'] == 'libraries':
                    libraries = payload['data']
                    print(f"[+] Found {len(libraries)} native libraries:")
                    print("-" * 100)
                    print(f"{'Name':<30} {'Base Address':<12} {'Size':<10} {'Path'}")
                    print("-" * 100)
                    
                    for lib in libraries:
                        size_kb = int(lib['size'], 16) // 1024 if isinstance(lib['size'], str) else lib['size'] // 1024
                        print(f"{lib['name']:<30} {lib['base']:<12} {size_kb:<10} {lib['path']}")
                        
                elif payload['type'] == 'error':
                    print(f"[-] {payload['message']}")
        
        try:
            device = self.get_device()
            
            if self.should_spawn:
                print(f"[+] Spawning package: {self.target}")
                pid = device.spawn([self.target])
                session = device.attach(pid)
                device.resume(pid)
                print(f"[+] Spawned and attached to PID: {pid}")
                # Wait for process to initialize
                time.sleep(3)
            else:
                print(f"[+] Attaching to PID: {self.target}")
                session = device.attach(self.target)
                print("[+] Attached successfully")
            
            script = session.create_script(enum_script)
            script.on('message', on_message)
            script.load()
            
            # Wait for enumeration to complete
            time.sleep(2)
            
            script.unload()
            session.detach()
            
        except Exception as e:
            print(f"[-] Error during library enumeration: {e}")

    def start_function_discovery(self, detailed=False):
        """Start the function discovery process"""
        print(f"[+] Starting function discovery for library: {self.library_path}")
        
        try:
            device = self.get_device()
            
            if self.should_spawn:
                print(f"[+] Spawning package: {self.target}")
                pid = device.spawn([self.target])
                self.session = device.attach(pid)
                device.resume(pid)
                print(f"[+] Spawned and attached to PID: {pid}")
            else:
                print(f"[+] Attaching to PID: {self.target}")
                self.session = device.attach(self.target)
                print("[+] Attached successfully")
            
            # Wait a bit for the process to initialize (especially important for spawn)
            if self.should_spawn:
                print("[+] Waiting for process to initialize...")
                time.sleep(3)
            
            # Discover functions
            if detailed:
                functions = self.discover_functions_with_details()
            else:
                functions = self.discover_all_functions()
                
        except Exception as e:
            print(f"[-] Error: {e}")
        
        finally:
            self.cleanup()
    
    def start_hooking(self):
        """Start the hooking process"""
        print(f"[+] Target library: {self.library_path}")
        print(f"[+] Function pattern: {self.pattern.pattern}")
        
        try:
            device = self.get_device()
            
            if self.should_spawn:
                print(f"[+] Spawning package: {self.target}")
                pid = device.spawn([self.target])
                self.session = device.attach(pid)
                device.resume(pid)
                print(f"[+] Spawned and attached to PID: {pid}")
            else:
                print(f"[+] Attaching to PID: {self.target}")
                self.session = device.attach(self.target)
                print("[+] Attached successfully")
            
            # Wait a bit for the process to initialize (especially important for spawn)
            if self.should_spawn:
                print("[+] Waiting for process to initialize...")
                time.sleep(3)
            
            # Find matching functions
            print("[+] Enumerating functions...")
            matching_functions = self.find_matching_functions()
            
            if not matching_functions:
                print("[-] No functions found matching the pattern")
                return
            
            print(f"[+] Found {len(matching_functions)} matching functions")
            
            # Create and load hook script
            hook_script = self.create_hook_script(matching_functions)
            self.script = self.session.create_script(hook_script)
            
            def on_message(message, data):
                if message['type'] == 'send':
                    print(f"[Script] {message['payload']}")
                elif message['type'] == 'error':
                    print(f"[Error] {message['description']}")
            
            self.script.on('message', on_message)
            self.script.load()
            
            print("[+] Hooks installed. Press Ctrl+C to stop...")
            
            # Keep the script running
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[+] Stopping...")
                
        except Exception as e:
            print(f"[-] Error: {e}")
        
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Clean up resources"""
        if self.script:
            self.script.unload()
        if self.session:
            self.session.detach()

def main():
    parser = argparse.ArgumentParser(description="Hook native methods in shared libraries using Frida")
    parser.add_argument("target", nargs="?", help="Package name (will spawn) or PID (will attach)")
    parser.add_argument("library", nargs="?", help="Shared library name or path (e.g., 'libnative.so')")
    parser.add_argument("pattern", nargs="?", help="Regex pattern to match function names")
    parser.add_argument("-d", "--device", help="Device ID to connect to (e.g., USB device ID)")
    parser.add_argument("-l", "--list-devices", action="store_true", help="List available devices")
    parser.add_argument("-p", "--list-processes", action="store_true", help="List processes on device")
    parser.add_argument("-m", "--list-libraries", action="store_true", help="List native libraries loaded by target process")
    parser.add_argument("-f", "--discover-functions", action="store_true", help="Discover all functions in the specified library")
    parser.add_argument("-F", "--discover-functions-detailed", action="store_true", help="Discover all functions with detailed information")
    
    args = parser.parse_args()
    
    # List devices if requested
    if args.list_devices:
        print("[+] Available devices:")
        try:
            devices = frida.enumerate_devices()
            for device in devices:
                print(f"    {device.id}: {device.name} ({device.type})")
        except Exception as e:
            print(f"[-] Error listing devices: {e}")
        return
    
    # Handle list processes
    if args.list_processes:
        # Create a dummy hooker just to list processes
        hooker = NativeMethodHooker("dummy", "dummy", "dummy", args.device)
        hooker.list_processes()
        return
    
    # Handle list libraries
    if args.list_libraries:
        if not args.target:
            parser.error("target is required when using -m/--list-libraries")
        hooker = NativeMethodHooker(args.target, "dummy", "dummy", args.device)
        hooker.list_loaded_libraries()
        return
    
    # Handle function discovery
    if args.discover_functions or args.discover_functions_detailed:
        if not args.target or not args.library:
            parser.error("target and library are required when using -f/--discover-functions or -F/--discover-functions-detailed")
        hooker = NativeMethodHooker(args.target, args.library, None, args.device)
        hooker.start_function_discovery(detailed=args.discover_functions_detailed)
        return
    
    # Check if required arguments are provided for hooking
    if not args.target or not args.library or not args.pattern:
        parser.error("target, library, and pattern are required unless using -l, -p, -m, -f, or -F")
    
    hooker = NativeMethodHooker(args.target, args.library, args.pattern, args.device)
    hooker.start_hooking()

if __name__ == "__main__":
    main()

# Example usage:
# List available devices
# python3 native_hooker.py -l

# List processes on specific device
# python3 native_hooker.py -p -d "14ed2fcc"

# List native libraries in a running app
# python3 native_hooker.py "com.example.app" -m
# python3 native_hooker.py "1234" -m

# Discover ALL functions in a library (NEW!)
# python3 native_hooker.py "com.example.app" "libnative.so" -f
# python3 native_hooker.py "1234" "libnative.so" -f

# Discover ALL functions with detailed info (NEW!)
# python3 native_hooker.py "com.example.app" "libnative.so" -F
# python3 native_hooker.py "1234" "libnative.so" -F

# Hook Android app by package name (will spawn) - match all functions
# python3 native_hooker.py "com.example.app" "libnative.so" ".*"

# Hook by PID (will attach)
# python3 native_hooker.py "1234" "libnative.so" "SSL_.*"

# Hook with specific USB device
# python3 native_hooker.py "com.example.app" "libnative.so" "Java_.*" -d "14ed2fcc"