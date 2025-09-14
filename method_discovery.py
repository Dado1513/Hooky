#!/usr/bin/env python3
"""
Method Discovery Helper for Frida
Helps you find available methods in a class before hooking
"""

import frida
import sys
import json
import re

class MethodDiscovery:
    def __init__(self, package_name, target_class):
        self.package_name = package_name
        self.target_class = target_class
        self.methods_info = []
        
    def discover_methods(self):
        """Discover all methods in the target class"""
        try:
            device = frida.get_usb_device()
            
            try:
                session = device.attach(self.package_name)
                print(f"[+] Attached to running process: {self.package_name}")
            except:
                pid = device.spawn([self.package_name])
                session = device.attach(pid)
                device.resume(pid)
                print(f"[+] Spawned and attached to: {self.package_name}")
            
            # JavaScript to discover methods
            js_code = f"""
            Java.perform(function() {{
                try {{
                    const targetClass = Java.use('{self.target_class}');
                    const methods = targetClass.class.getDeclaredMethods();
                    
                    const methodsInfo = [];
                    
                    methods.forEach(function(method) {{
                        const methodName = method.getName();
                        if (methodName.includes('<init>') || methodName.includes('<clinit>')) {{
                            return;
                        }}
                        
                        const paramTypes = method.getParameterTypes();
                        const paramNames = [];
                        for (let i = 0; i < paramTypes.length; i++) {{
                            paramNames.push(paramTypes[i].getName());
                        }}
                        
                        const returnType = method.getReturnType().getName();
                        const modifiers = method.getModifiers();
                        
                        methodsInfo.push({{
                            name: methodName,
                            parameters: paramNames,
                            returnType: returnType,
                            modifiers: modifiers,
                            signature: methodName + '(' + paramNames.join(', ') + ')'
                        }});
                    }});
                    
                    send({{
                        type: 'methods_discovered',
                        class_name: '{self.target_class}',
                        methods: methodsInfo
                    }});
                    
                }} catch (e) {{
                    send({{
                        type: 'error',
                        message: 'Error discovering methods: ' + e.message
                    }});
                }}
            }});
            """
            
            script = session.create_script(js_code)
            
            def on_message(message, data):
                if message['type'] == 'send':
                    payload = message['payload']
                    if payload['type'] == 'methods_discovered':
                        self.methods_info = payload['methods']
                        print(f"[+] Discovered {len(self.methods_info)} methods")
                    elif payload['type'] == 'error':
                        print(f"[-] {payload['message']}")
                elif message['type'] == 'error':
                    print(f"[ERROR] {message['description']}")
            
            script.on('message', on_message)
            script.load()
            
            # Wait a moment for discovery
            import time
            time.sleep(2)
            
            session.detach()
            
        except Exception as e:
            print(f"[-] Error: {e}")
    
    def display_methods(self, filter_pattern=None):
        """Display discovered methods with optional filtering"""
        if not self.methods_info:
            print("[-] No methods discovered. Run discover_methods() first.")
            return
        
        filtered_methods = self.methods_info
        
        if filter_pattern:
            try:
                regex = re.compile(filter_pattern, re.IGNORECASE)
                filtered_methods = [m for m in self.methods_info if regex.search(m['name'])]
            except re.error:
                # Fallback to simple string matching
                filtered_methods = [m for m in self.methods_info if filter_pattern.lower() in m['name'].lower()]
        
        if not filtered_methods:
            print(f"[-] No methods found matching pattern: {filter_pattern}")
            return
        
        print(f"\n{'='*80}")
        print(f"METHODS IN {self.target_class}")
        if filter_pattern:
            print(f"FILTERED BY: {filter_pattern}")
        print(f"{'='*80}")
        
        # Group methods by category
        categories = {
            'Authentication': ['auth', 'login', 'password', 'credential', 'verify', 'validate'],
            'Security': ['security', 'encrypt', 'decrypt', 'hash', 'key', 'token', 'signature'],
            'Network': ['http', 'url', 'request', 'response', 'connection', 'network'],
            'Data': ['data', 'json', 'xml', 'parse', 'serialize', 'convert'],
            'Other': []
        }
        
        categorized = {cat: [] for cat in categories}
        
        for method in filtered_methods:
            method_name_lower = method['name'].lower()
            assigned = False
            
            for category, keywords in categories.items():
                if category == 'Other':
                    continue
                    
                if any(keyword in method_name_lower for keyword in keywords):
                    categorized[category].append(method)
                    assigned = True
                    break
            
            if not assigned:
                categorized['Other'].append(method)
        
        # Display categorized methods
        for category, methods in categorized.items():
            if not methods:
                continue
                
            print(f"\n📂 {category.upper()} METHODS ({len(methods)}):")
            print("-" * 60)
            
            for i, method in enumerate(methods, 1):
                # Format modifiers
                mod_flags = []
                modifiers = method['modifiers']
                if modifiers & 1: mod_flags.append('public')
                elif modifiers & 2: mod_flags.append('private')
                elif modifiers & 4: mod_flags.append('protected')
                if modifiers & 8: mod_flags.append('static')
                if modifiers & 16: mod_flags.append('final')
                
                mod_str = ' '.join(mod_flags)
                
                print(f"  {i:2d}. {method['name']}")
                print(f"      Signature: {mod_str} {method['returnType']} {method['signature']}")
                
                if method['parameters']:
                    print(f"      Parameters: {len(method['parameters'])}")
                    for j, param in enumerate(method['parameters']):
                        print(f"        [{j}] {param}")
                else:
                    print(f"      Parameters: None")
                print()
    
    def save_methods(self, filename):
        """Save discovered methods to JSON file"""
        if not self.methods_info:
            print("[-] No methods to save. Run discover_methods() first.")
            return
        
        data = {
            'class_name': self.target_class,
            'package_name': self.package_name,
            'total_methods': len(self.methods_info),
            'methods': self.methods_info
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[+] Methods saved to {filename}")
    
    def suggest_filters(self):
        """Suggest useful method filters based on discovered methods"""
        if not self.methods_info:
            print("[-] No methods discovered. Run discover_methods() first.")
            return
        
        print(f"\n🎯 SUGGESTED METHOD FILTERS FOR {self.target_class}")
        print("=" * 60)
        
        # Common patterns
        suggestions = []
        
        # Authentication methods
        auth_methods = [m for m in self.methods_info if any(kw in m['name'].lower() for kw in ['auth', 'login', 'password', 'verify', 'validate', 'check'])]
        if auth_methods:
            suggestions.append(("Authentication", "auth.*|login.*|.*password.*|verify.*|validate.*|check.*", len(auth_methods)))
        
        # Security methods
        security_methods = [m for m in self.methods_info if any(kw in m['name'].lower() for kw in ['encrypt', 'decrypt', 'hash', 'key', 'token', 'security', 'crypto'])]
        if security_methods:
            suggestions.append(("Security/Crypto", ".*encrypt.*|.*decrypt.*|.*hash.*|.*key.*|.*token.*|.*security.*|.*crypto.*", len(security_methods)))
        
        # Network methods
        network_methods = [m for m in self.methods_info if any(kw in m['name'].lower() for kw in ['http', 'url', 'request', 'response', 'network', 'connection'])]
        if network_methods:
            suggestions.append(("Network", ".*http.*|.*url.*|.*request.*|.*response.*|.*network.*|.*connection.*", len(network_methods)))
        
        # Getters/Setters
        getters = [m for m in self.methods_info if m['name'].startswith('get')]
        setters = [m for m in self.methods_info if m['name'].startswith('set')]
        if getters:
            suggestions.append(("Getters", "get.*", len(getters)))
        if setters:
            suggestions.append(("Setters", "set.*", len(setters)))
        
        # Boolean methods (likely checks)
        bool_methods = [m for m in self.methods_info if m['returnType'] == 'boolean']
        if bool_methods:
            suggestions.append(("Boolean Returns (Checks)", "is.*|has.*|can.*|should.*|check.*", len(bool_methods)))
        
        for i, (category, pattern, count) in enumerate(suggestions, 1):
            print(f"{i}. {category} ({count} methods)")
            print(f"   Filter: '{pattern}'")
            print(f"   Usage: python frida_interactive.py {self.package_name} {self.target_class} '{pattern}'")
            print()
        
        # Top methods by name frequency
        method_words = {}
        for method in self.methods_info:
            # Split camelCase and get individual words
            words = re.findall(r'[A-Z][a-z]*|[a-z]+', method['name'])
            for word in words:
                if len(word) > 2:  # Skip very short words
                    word_lower = word.lower()
                    method_words[word_lower] = method_words.get(word_lower, 0) + 1
        
        if method_words:
            print("🔤 COMMON METHOD WORDS (for custom filters):")
            print("-" * 40)
            sorted_words = sorted(method_words.items(), key=lambda x: x[1], reverse=True)[:10]
            for word, count in sorted_words:
                print(f"   '{word}.*' ({count} methods)")

def main():
    if len(sys.argv) < 3:
        print("Method Discovery Helper for Frida")
        print("=" * 40)
        print("Usage:")
        print(f"  {sys.argv[0]} <package_name> <target_class> [options]")
        print()
        print("Options:")
        print("  --filter <pattern>    Filter methods by pattern")
        print("  --save <filename>     Save methods to JSON file")
        print("  --suggest             Show suggested filters")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} com.example.app com.example.AuthManager")
        print(f"  {sys.argv[0]} com.example.app com.example.AuthManager --filter 'auth.*'")
        print(f"  {sys.argv[0]} com.example.app com.example.AuthManager --save methods.json")
        print(f"  {sys.argv[0]} com.example.app com.example.AuthManager --suggest")
        sys.exit(1)
    
    package_name = sys.argv[1]
    target_class = sys.argv[2]
    
    discoverer = MethodDiscovery(package_name, target_class)
    
    print(f"[+] Discovering methods in {target_class}...")
    discoverer.discover_methods()
    
    # Parse additional options
    filter_pattern = None
    save_file = None
    show_suggestions = False
    
    i = 3
    while i < len(sys.argv):
        if sys.argv[i] == '--filter' and i + 1 < len(sys.argv):
            filter_pattern = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--save' and i + 1 < len(sys.argv):
            save_file = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--suggest':
            show_suggestions = True
            i += 1
        else:
            i += 1
    
    # Display methods
    discoverer.display_methods(filter_pattern)
    
    # Save if requested
    if save_file:
        discoverer.save_methods(save_file)
    
    # Show suggestions if requested
    if show_suggestions:
        discoverer.suggest_filters()

if __name__ == "__main__":
    main()