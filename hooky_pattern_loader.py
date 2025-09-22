#!/usr/bin/env python3
"""
Frida Pattern Loader
Advanced pattern-based hooking tool for penetration testing
Supports config files, command-line patterns, and interactive mode
"""

import argparse
import json
import sys
import time
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
import frida
from frida.core import Session, Device
from banner import show_banner, Colors


class FridaPatternLoader:
    def __init__(self):
        self.device: Optional[Device] = None
        self.session: Optional[Session] = None
        self.script = None
        self.patterns: Dict[str, Dict] = {}
        self.config: Dict = {}
        self.current_pid = None
        
        # Default configuration
        self.default_config = {
            'device': 'usb',
            'spawn_mode': True,
            'auto_resume': True,
            'log_level': 'INFO',
            'hook_timeout': 100,
            'max_matches': 100,
            'enable_stack_trace': False,
            'enable_arg_dump': True,
            'enable_retval_decoding': True,  # New option
            'max_string_length': 1000,       # New option
            'output_format': 'colored'
        }
    
    def load_config_file(self, config_path: str) -> Dict:
        """Load configuration from YAML or JSON file"""
        config_file = Path(config_path)
        
        if not config_file.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
        
        try:
            with open(config_file, 'r') as f:
                if config_file.suffix.lower() in ['.yml', '.yaml']:
                    config = yaml.safe_load(f)
                else:
                    config = json.load(f)
            
            print(f"[+] Loaded config from: {config_path}")
            return config
            
        except Exception as e:
            raise Exception(f"Failed to load config file: {e}")
    
    def load_patterns_from_config(self, config: Dict):
        """Load patterns from configuration"""
        if 'patterns' in config:
            for pattern_name, pattern_data in config['patterns'].items():
                if isinstance(pattern_data, str):
                    # Simple pattern string
                    self.patterns[pattern_name] = {
                        'pattern': pattern_data,
                        'description': f'Pattern {pattern_name}',
                        'enabled': True
                    }
                else:
                    # Full pattern configuration
                    self.patterns[pattern_name] = {
                        'pattern': pattern_data.get('pattern', ''),
                        'description': pattern_data.get('description', f'Pattern {pattern_name}'),
                        'regex': pattern_data.get('regex'),
                        'enabled': pattern_data.get('enabled', True),
                        'on_enter': pattern_data.get('on_enter'),
                        'on_leave': pattern_data.get('on_leave')
                    }
    
    def load_patterns_from_json(self, json_path: str):
        """Load simple patterns from JSON file with only pattern, regex, description, enabled fields"""
        json_file = Path(json_path)
        
        if not json_file.exists():
            raise FileNotFoundError(f"JSON pattern file not found: {json_path}")
        
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            # Handle different JSON structures
            if isinstance(data, dict):
                if 'patterns' in data:
                    # Structure: {"patterns": {"name": {...}}}
                    patterns_data = data['patterns']
                else:
                    # Structure: {"name": {...}}
                    patterns_data = data
            elif isinstance(data, list):
                # Structure: [{"name": "...", "pattern": "...", ...}]
                patterns_data = {}
                for item in data:
                    if 'name' in item:
                        name = item['name']
                        patterns_data[name] = {k: v for k, v in item.items() if k != 'name'}
                    else:
                        print(f"[!] Skipping pattern without 'name' field: {item}")
                        continue
            else:
                raise ValueError("JSON must be object or array")
            
            # Load patterns with only the 4 allowed fields
            for pattern_name, pattern_data in patterns_data.items():
                if isinstance(pattern_data, str):
                    # Simple string pattern
                    self.patterns[pattern_name] = {
                        'pattern': pattern_data,
                        'description': f'Pattern {pattern_name}',
                        'enabled': True,
                        'regex': None
                    }
                else:
                    # Filter to only allowed fields
                    allowed_fields = ['pattern', 'regex', 'description', 'enabled']
                    filtered_data = {}
                    
                    for field in allowed_fields:
                        if field in pattern_data:
                            filtered_data[field] = pattern_data[field]
                    
                    # Set defaults for missing required fields
                    self.patterns[pattern_name] = {
                        'pattern': filtered_data.get('pattern', ''),
                        'description': filtered_data.get('description', f'Pattern {pattern_name}'),
                        'regex': filtered_data.get('regex'),
                        'enabled': filtered_data.get('enabled', True)
                    }
                    
                    # Warn about ignored fields
                    ignored_fields = set(pattern_data.keys()) - set(allowed_fields)
                    if ignored_fields:
                        print(f"[!] Ignored unsupported fields in pattern '{pattern_name}': {', '.join(ignored_fields)}")
            
            print(f"[+] Loaded {len(self.patterns)} patterns from JSON: {json_path}")
            
        except Exception as e:
            raise Exception(f"Failed to load JSON pattern file: {e}")
    
    def add_pattern_from_args(self, name: str, pattern: str, description: str = None):
        """Add pattern from command line arguments"""
        self.patterns[name] = {
            'pattern': pattern,
            'description': description or f'Pattern {name}',
            'enabled': True
        }
        print(f"[+] Added pattern: {name} -> {pattern}")
    
    def connect_device(self, device_type: str = 'usb') -> Device:
        """Connect to Frida device"""
        try:
            if device_type == 'usb':
                device = frida.get_usb_device()
                print("[+] Connected to USB device")
            elif device_type == 'local':
                device = frida.get_local_device()
                print("[+] Connected to local device")
            else:
                # Try to connect by device ID
                device = frida.get_device(device_type)
                print(f"[+] Connected to device: {device_type}")
            
            self.device = device
            return device
            
        except Exception as e:
            raise Exception(f"Failed to connect to device '{device_type}': {e}")
    
    def find_target_process(self, target: str):
        """Find target process by name or bundle ID"""
        try:
            processes = self.device.enumerate_processes()
            
            # Exact match first
            for process in processes:
                if target == process.name:
                    return process
            
            # Partial match
            for process in processes:
                if target in process.name:
                    return process
            
            # For iOS apps, try to find by bundle identifier
            applications = self.device.enumerate_applications()
            for app in applications:
                if target == app.identifier or target in app.name:
                    print(f"[+] Found app: {app.name} ({app.identifier})")
                    return None  # Will try to spawn by identifier
            
            return None
            
        except Exception as e:
            print(f"[!] Error finding target process: {e}")
            return None

    def start_session(self, target: str, spawn_mode: bool = True) -> Session:
        """Start Frida session with target application"""
        try:
            pid = None
            if spawn_mode:
                print(f"[+] Spawning: {target}")
                pid = self.device.spawn([target])
                session = self.device.attach(pid)
                self.current_pid = pid
                
                if self.config.get('auto_resume', True):
                    self.device.resume(pid)
                    print("[+] Process resumed")
            else:
                print(f"[+] Attaching to: {target}")
                # Target can be PID (int) or process name (str)
                if isinstance(target, str) and target.isdigit():
                    pid = int(target)
                    session = self.device.attach(pid)
                    self.current_pid = pid
                else:
                    # Try to find process by name
                    processes = self.device.enumerate_processes()
                    target_process = None
                    
                    for process in processes:
                        if target in process.name or target == process.name:
                            target_process = process
                            break
                    
                    if target_process:
                        pid = target_process.pid
                        session = self.device.attach(pid)
                        self.current_pid = pid
                        print(f"[+] Found process: {target_process.name} (PID: {pid})")
                    else:
                        session = self.device.attach(target)
                        self.current_pid = target  # Could be bundle ID
            
            self.session = session
            print(f"[+] Session established (PID: {self.current_pid})")
            return session
            
        except Exception as e:
            raise Exception(f"Failed to start session with '{target}': {e}")
    
    def generate_frida_script(self) -> str:
        """Generate the complete Frida script with patterns"""
        
        # Base modular hooker script (embedded)
        base_script = """
/**
 * Modular Frida Script for Pattern-Based Method Hooking
 * Auto-generated by FridaPatternLoader
 */

class PatternHooker {
    constructor(config = {}) {
        this.config = {
            logLevel: config.logLevel || 'INFO',
            hookTimeout: config.hookTimeout || 100,
            maxMatches: config.maxMatches || 50,
            enableStackTrace: config.enableStackTrace || false,
            enableArgDump: config.enableArgDump || true,
            ...config
        };
        this.hooks = new Map();
        this.patterns = new Map();
    }

    log(level, message) {
        const levels = { ERROR: 0, WARN: 1, INFO: 2, DEBUG: 3 };
        if (levels[level] <= levels[this.config.logLevel]) {
            console.log(`[${level}] ${new Date().toISOString()} - ${message}`);
        }
    }

    addPattern(name, pattern, options = {}) {
        const cleanPattern = pattern.replace(/\\s+/g, ' ').trim();
        this.patterns.set(name, {
            pattern: cleanPattern,
            regex: options.regex || null,
            description: options.description || name,
            onEnter: options.onEnter || this.defaultOnEnter.bind(this),
            onLeave: options.onLeave || this.defaultOnLeave.bind(this),
            enabled: options.enabled !== false
        });
        this.log('DEBUG', `Added pattern: ${name} - ${cleanPattern}`);
    }

    defaultOnEnter(args, context) {
        this.log('INFO', `[${context.patternName}] Method called at ${context.address}`);
        if (this.config.enableArgDump) {
             let argsLength = 0;
            try {
                argsLength = args.length || 0;
            } catch (e) {
                this.log('DEBUG', '    Cannot determine args length, skipping argument dump');
                return;
            }
            for (let i = 0; i < Math.min(argsLength, 6); i++) {
                try {
                    const arg = args[i];
                    let argInfo = `x${i}: ${arg}`;
                    
                    if (arg && !arg.isNull()) {
                        try {
                            const str = Memory.readUtf8String(arg, 100);
                            if (str && str.length > 0 && /^[\\x20-\\x7E]*$/.test(str)) {
                                argInfo += ` ("${str}")`;
                            }
                        } catch (e) {
                            try {
                                const ptr = Memory.readPointer(arg);
                                argInfo += ` (ptr: ${ptr})`;
                            } catch (e2) {
                                // Just show raw value
                            }
                        }
                    }
                    this.log('INFO', `    ${argInfo}`);
                } catch (e) {
                    this.log('DEBUG', `    x${i}: <unreadable>`);
                }
            }
        }

        if (this.config.enableStackTrace) {
            this.log('DEBUG', 'Stack trace:');
            Thread.backtrace(this.context(), Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress)
                .forEach(symbol => this.log('DEBUG', `    ${symbol}`));
        }
    }

    /*defaultOnLeave(retval, context) {
        this.log('INFO', `[${context.patternName}] Return value: ${retval}`);
    }*/
    defaultOnLeave(retval, context) {
        this.log('INFO', `[${context.patternName}] Return value: ${retval}`);
        
        // Enhanced return value decoding
        if (retval && !retval.isNull()) {
            try {
                // Try to decode as different data types
                const decodedValues = this.decodeReturnValue(retval);
                
                for (const [type, value] of Object.entries(decodedValues)) {
                    if (value !== null) {
                        this.log('INFO', `[${context.patternName}] Decoded as ${type}: ${value}`);
                    }
                }
            } catch (e) {
                this.log('DEBUG', `[${context.patternName}] Error decoding return value: ${e.message}`);
            }
        }
    }

   
    decodeReturnValue(retval) {
        const decoded = {};
        
        try {
            // Always show raw pointer
            decoded.pointer = retval.toString();
            
            // Try integer conversion (safest operation)
            try {
                const intValue = retval.toInt32();
                decoded.integer = intValue;
                
                if (intValue === 0 || intValue === 1) {
                    decoded.boolean = intValue === 1;
                }
                
                // Try unsigned integers
                const uintValue = retval.toUInt32();
                if (uintValue !== intValue && uintValue > 0) {
                    decoded.uint32 = uintValue;
                }
                
                // Try uint64 if different from 32-bit values
                try {
                    const uint64Value = uint64(retval.toString()).toNumber();
                    if (uint64Value !== intValue && uint64Value !== uintValue && isFinite(uint64Value)) {
                        decoded.uint64 = uint64Value;
                    }
                } catch (e) {
                    // Skip uint64 conversion
                }
            } catch (e) {
                // Skip integer conversion
            }
            
            // Try double/float conversion at pointer location (if pointer looks valid)
            if (!retval.isNull()) {
                const ptrInt = parseInt(retval.toString(), 16);
                if (ptrInt > 0x1000 && ptrInt < 0x7fffffffff) {
                    try {
                        const doubleValue = Memory.readDouble(retval);
                        if (isFinite(doubleValue) && !isNaN(doubleValue) && doubleValue !== 0) {
                            decoded.double = doubleValue;
                        }
                        
                        const floatValue = Memory.readFloat(retval);
                        if (isFinite(floatValue) && !isNaN(floatValue) && 
                            Math.abs(floatValue - doubleValue) > 0.0001 && floatValue !== 0) {
                            decoded.float = floatValue;
                        }
                    } catch (e) {
                        // Skip float/double conversion
                    }
                    
                    // Try C string conversion
                    try {
                        // Quick check - read first 4 bytes to see if it looks like text
                        const firstBytes = Memory.readByteArray(retval, 4);
                        if (firstBytes) {
                            const bytes = new Uint8Array(firstBytes);
                            let printableCount = 0;
                            
                            for (let i = 0; i < bytes.length; i++) {
                                if (bytes[i] === 0) break; // null terminator
                                if (bytes[i] >= 32 && bytes[i] <= 126) { // printable ASCII
                                    printableCount++;
                                }
                            }
                            
                            // If at least 2 printable chars in first 4 bytes, try reading string
                            if (printableCount >= 2) {
                                const stringValue = Memory.readUtf8String(retval, 200);
                                if (stringValue && stringValue.length > 0 && stringValue.trim().length > 0) {
                                    // Additional validation - avoid control characters
                                    if (!/[\\x00-\\x08\\x0E-\\x1F\\x7F]/.test(stringValue)) {
                                        decoded.string = stringValue.length > 100 ? 
                                            stringValue.substring(0, 100) + '...' : stringValue;
                                    }
                                }
                            }
                        }
                    } catch (e) {
                        // Skip C string conversion
                    }
                }
            }
            
            // Try ObjC string conversion if pointer looks reasonable
            if (typeof ObjC !== 'undefined' && !retval.isNull()) {
                decoded.nsstring = ObjC.Object(retval).toString();

            }
            
        } catch (e) {
            this.log('DEBUG', `Decode error: ${e.message}`);
        }
        
        return decoded;
    }

    hookMethod(address, patternName, patternConfig) {
        if (this.hooks.has(address.toString())) {
            this.log('WARN', `Address ${address} already hooked`);
            return;
        }

        try {
            const self = this; // Capture reference for closure
            const hook = Interceptor.attach(address, {
                onEnter: function(args) {
                    const context = {
                        address: address.toString(),
                        patternName: patternName,
                        timestamp: Date.now()
                    };
                    // Store context in a way that works with Frida's Interceptor
                    this.hookContext = context;
                    patternConfig.onEnter.call(this, args, context);
                },
                onLeave: function(retval) {
                    // Retrieve context from the stored property
                    const context = this.hookContext || {
                        address: address.toString(),
                        patternName: patternName,
                        timestamp: Date.now()
                    };
                    patternConfig.onLeave.call(this, retval, context);
                }
            });

            this.hooks.set(address.toString(), {
                hook: hook,
                patternName: patternName,
                address: address.toString()
            });

            this.log('INFO', `[${patternName}] Hooked method at ${address}`);
        } catch (e) {
            this.log('ERROR', `Failed to hook ${address}: ${e.message}`);
        }
    }

    searchPatterns(rangeFilter = null) {
        this.log('INFO', 'Starting pattern search...');
        
        const ranges = Process.enumerateRangesSync('r-x').filter(range => {
            if (rangeFilter) {
                return rangeFilter(range);
            }
            return range.size > 0x1000;
        });

        this.log('INFO', `Scanning ${ranges.length} memory ranges`);

        let totalMatches = 0;
        for (const [patternName, patternConfig] of this.patterns) {
            if (!patternConfig.enabled) continue;

            this.log('DEBUG', `Searching for pattern: ${patternName}`);
            let patternMatches = 0;

            for (const range of ranges) {
                try {
                    const matches = Memory.scanSync(range.base, range.size, patternConfig.pattern);
                    
                    for (const match of matches) {
                        if (totalMatches >= this.config.maxMatches) {
                            this.log('WARN', `Reached maximum matches limit (${this.config.maxMatches})`);
                            return totalMatches;
                        }

                        if (patternConfig.regex) {
                            const symbol = DebugSymbol.fromAddress(match.address);
                            if (!patternConfig.regex.test(symbol.name || '')) {
                                continue;
                            }
                        }

                        this.log('INFO', `[${patternName}] Pattern found at: ${match.address} (${range.file?.path || 'unknown'})`);
                        this.hookMethod(match.address, patternName, patternConfig);
                        patternMatches++;
                        totalMatches++;
                    }
                } catch (e) {
                    this.log('DEBUG', `Error scanning range ${range.base}: ${e.message}`);
                }
            }

            this.log('INFO', `[${patternName}] Found ${patternMatches} matches`);
        }

        this.log('INFO', `Pattern search complete. Total matches: ${totalMatches}`);
        return totalMatches;
    }

    unhookAll() {
        this.log('INFO', 'Removing all hooks...');
        for (const [address, hookInfo] of this.hooks) {
            try {
                hookInfo.hook.detach();
                this.log('DEBUG', `Unhooked ${hookInfo.patternName} at ${address}`);
            } catch (e) {
                this.log('ERROR', `Failed to unhook ${address}: ${e.message}`);
            }
        }
        this.hooks.clear();
    }

    getStats() {
        return {
            totalPatterns: this.patterns.size,
            enabledPatterns: Array.from(this.patterns.values()).filter(p => p.enabled).length,
            activeHooks: this.hooks.size,
            patterns: Object.fromEntries(this.patterns)
        };
    }
}

// Initialize hooker with configuration
const hookerConfig = %s;
const hooker = new PatternHooker(hookerConfig);

// Add patterns from configuration
%s

// Auto-start pattern search
function initializeHooking() {
    setTimeout(() => {
        const matches = hooker.searchPatterns();
        console.log(`[SUMMARY] Setup complete. Found ${matches} matches.`);
        console.log('[STATS]', JSON.stringify(hooker.getStats(), null, 2));
    }, hookerConfig.hookTimeout);
}

// Global functions for interactive use
globalThis.hooker = hooker;
globalThis.addPattern = hooker.addPattern.bind(hooker);
globalThis.searchPatterns = hooker.searchPatterns.bind(hooker);
globalThis.unhookAll = hooker.unhookAll.bind(hooker);
globalThis.getStats = hooker.getStats.bind(hooker);

// Start hooking
initializeHooking();
        """
        
        # Generate hooker configuration
        hooker_config = {
            'logLevel': self.config.get('log_level', 'INFO'),
            'hookTimeout': self.config.get('hook_timeout', 100),
            'maxMatches': self.config.get('max_matches', 100),
            'enableStackTrace': self.config.get('enable_stack_trace', False),
            'enableArgDump': self.config.get('enable_arg_dump', True),
            'enableRetvalDecoding': self.config.get('enable_retval_decoding', True),
            'maxStringLength': self.config.get('max_string_length', 1000)
        }
        
        
        # Generate pattern additions
        pattern_additions = []
        for name, pattern_data in self.patterns.items():
            if not pattern_data.get('enabled', True):
                continue
                
            options = {
                'description': pattern_data.get('description', name),
                'enabled': pattern_data.get('enabled', True)
            }
            
            if pattern_data.get('regex'):
                options['regex'] = f"/{pattern_data['regex']}/i"
            
            if pattern_data.get('on_enter'):
                options['onEnter'] = pattern_data['on_enter']
            
            if pattern_data.get('on_leave'):
                options['onLeave'] = pattern_data['on_leave']
            
            pattern_line = f"hooker.addPattern('{name}', '{pattern_data['pattern']}', {json.dumps(options)});"
            pattern_additions.append(pattern_line)
        
        return base_script % (
            json.dumps(hooker_config, indent=2),
            '\n'.join(pattern_additions)
        )
    
    def load_and_run_script(self):
        """Load the generated script into Frida session"""
        if not self.session:
            raise Exception("No active session. Call start_session() first.")
        
        script_code = self.generate_frida_script()
        
        try:
            self.script = self.session.create_script(script_code)
            
            # Set up message handler
            def on_message(message, data):
                if message['type'] == 'log':
                    print(f"[FRIDA] {message['payload']}")
                elif message['type'] == 'error':
                    print(f"[ERROR] {message['description']}")
                    if 'stack' in message:
                        print(f"[STACK] {message['stack']}")
                elif message['type'] == 'send':
                    print(f"[MESSAGE] {message['payload']}")
                else:
                    print(f"[DEBUG] {message}")
            
            self.script.on('message', on_message)
            self.script.load()
            
            # Wait a bit for script to initialize
            time.sleep(0.5)
            
            print("[+] Script loaded and running")
            print(f"[+] Monitoring PID: {self.current_pid}")
            return self.script
            
        except Exception as e:
            raise Exception(f"Failed to load script: {e}")
    
    def run_interactive(self):
        """Run in interactive mode"""
        print("\n[+] Interactive mode - Available commands:")
        print("  stats       - Show hooking statistics")
        print("  patterns    - List loaded patterns")
        print("  search      - Re-run pattern search")
        print("  unhook      - Remove all hooks")
        print("  processes   - List device processes")
        print("  modules     - List loaded modules")
        print("  pid         - Show current PID")
        print("  help        - Show this help")
        print("  quit        - Exit")
        print()
        
        try:
            while True:
                try:
                    cmd = input("frida-patterns> ").strip().lower()
                    
                    if cmd in ['quit', 'exit', 'q']:
                        break
                    elif cmd == 'stats':
                        try:
                            result = self.script.exports_sync.get_stats()
                            print("Hook Statistics:", json.dumps(result, indent=2))
                        except AttributeError:
                            print("[!] Stats function not available. Script may not be fully loaded.")
                        except Exception as e:
                            print(f"[!] Error getting stats: {e}")
                    elif cmd == 'patterns':
                        print("\nLoaded Patterns:")
                        for name, pattern in self.patterns.items():
                            enabled = "✓" if pattern.get('enabled', True) else "✗"
                            regex_info = f" (regex: {pattern['regex']})" if pattern.get('regex') else ""
                            print(f"  {enabled} {name}: {pattern['pattern'][:50]}...{regex_info}")
                            print(f"    Description: {pattern.get('description', 'N/A')}")
                    elif cmd == 'search':
                        try:
                            self.script.exports_sync.search_patterns()
                        except AttributeError:
                            print("[!] Search function not available.")
                        except Exception as e:
                            print(f"[!] Error running search: {e}")
                    elif cmd == 'unhook':
                        try:
                            self.script.exports_sync.unhook_all()
                            print("[+] All hooks removed")
                        except AttributeError:
                            print("[!] Unhook function not available.")
                        except Exception as e:
                            print(f"[!] Error unhooking: {e}")
                    elif cmd == 'processes':
                        try:
                            processes = self.device.enumerate_processes()
                            print("\nRunning Processes:")
                            for proc in processes[:20]:  # Show first 20
                                print(f"  {proc.pid:>6}: {proc.name}")
                            if len(processes) > 20:
                                print(f"  ... and {len(processes) - 20} more")
                        except Exception as e:
                            print(f"[!] Error listing processes: {e}")
                    elif cmd == 'modules':
                        try:
                            if self.session:
                                modules = self.session.enumerate_modules()
                                print("\nLoaded Modules:")
                                for module in modules[:15]:  # Show first 15
                                    print(f"  {module.name}: {module.base_address}")
                                if len(modules) > 15:
                                    print(f"  ... and {len(modules) - 15} more")
                            else:
                                print("[!] No active session")
                        except Exception as e:
                            print(f"[!] Error listing modules: {e}")
                    elif cmd == 'pid':
                        print(f"Current PID: {self.current_pid}")
                    elif cmd == 'help':
                        print("Available commands:")
                        print("  stats, patterns, search, unhook, processes, modules, pid, help, quit")
                    elif cmd:
                        print(f"Unknown command: {cmd}. Type 'help' for available commands.")
                        
                except KeyboardInterrupt:
                    print("\nUse 'quit' to exit")
                except Exception as e:
                    print(f"Error: {e}")
                    
        except KeyboardInterrupt:
            print("\n[+] Exiting interactive mode...")
    
    def cleanup(self):
        """Clean up resources"""
        try:
            if self.script:
                self.script.unload()
                print("[+] Script unloaded")
        except Exception as e:
            print(f"[!] Error unloading script: {e}")
        
        try:
            if self.session:
                self.session.detach()
                print("[+] Session detached")
        except Exception as e:
            print(f"[!] Error detaching session: {e}")
        
        print("[+] Cleanup complete")

def create_sample_config():
    """Create a sample configuration file"""
    sample_config = {
        'device': 'usb',
        'spawn_mode': True,
        'auto_resume': True,
        'log_level': 'INFO',
        'hook_timeout': 100,
        'max_matches': 100,
        'enable_stack_trace': False,
        'enable_arg_dump': True,
        'patterns': {
            'setPasswordProperty': {
                'pattern': 'a1 18 00 f0 21 ec 45 f9 70 0d 00 b0 10 5a 41 f9 00 02 1f d6',
                'description': 'Password property setter with hardcoded value',
                'enabled': True
            },
            'ssl_pinning_check': {
                'pattern': '?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 01 ?? ??',
                'regex': 'SSLSetSessionOption|SSLHandshake|SecTrustEvaluate',
                'description': 'SSL/TLS security validation methods',
                'enabled': True
            },
            'jailbreak_detection': {
                'pattern': '?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??',
                'regex': 'stat|access|fopen.*cydia|substrate',
                'description': 'Jailbreak detection patterns',
                'enabled': True
            }
        }
    }
    
    return sample_config

def main():
    show_banner()
    parser = argparse.ArgumentParser(
        description='Frida Pattern Loader - Advanced pattern-based hooking for penetration testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Load patterns from config file
  python frida_loader.py -c patterns.yml -t com.example.app
  
  # Load simple JSON patterns (only pattern, regex, description, enabled)
  python frida_loader.py -j simple_patterns.json -t com.example.app
  
  # Add single pattern via command line
  python frida_loader.py -t com.example.app -p "setPassword:a1 18 00 f0 21 ec 45 f9"
  
  # Mix JSON patterns with command line patterns
  python frida_loader.py -j patterns.json -p "custom:?? ?? ?? ??" -t app
  
  # Generate sample config
  python frida_loader.py --sample-config > patterns.yml
        """
    )
    
    parser.add_argument('-c', '--config', type=str, help='Configuration file (YAML/JSON)')
    parser.add_argument('-j', '--json-patterns', type=str, help='Simple JSON pattern file (pattern, regex, description, enabled only)')
    parser.add_argument('-t', '--target', type=str, help='Target application (bundle ID or process name)')
    parser.add_argument('-d', '--device', type=str, default='usb', help='Device type: usb, local, or device ID')
    parser.add_argument('-p', '--pattern', action='append', help='Pattern in format "name:hex_pattern"')
    parser.add_argument('--attach', action='store_true', help='Attach mode (default: spawn)')
    parser.add_argument('--no-resume', action='store_true', help='Don\'t auto-resume spawned process')
    parser.add_argument('-i', '--interactive', action='store_true', help='Run in interactive mode')
    parser.add_argument('--sample-config', action='store_true', help='Generate sample configuration file')
    parser.add_argument('--log-level', choices=['ERROR', 'WARN', 'INFO', 'DEBUG'], default='INFO')
    parser.add_argument('--max-matches', type=int, default=100, help='Maximum pattern matches')
    parser.add_argument('--timeout', type=int, default=100, help='Hook timeout in milliseconds')
    parser.add_argument('--stack-trace', action='store_true', help='Enable stack traces')
    parser.add_argument('--no-arg-dump', action='store_true', help='Disable argument dumping')
    parser.add_argument('--no-retval-decode', action='store_true', help='Disable return value decoding')
    parser.add_argument('--max-string-length', type=int, default=1000, help='Maximum string length to read')

    
    args = parser.parse_args()
    
    if args.sample_config:
        config = create_sample_config()
        print(yaml.dump(config, default_flow_style=False))
        return
    
    if not args.target and not args.config and not args.json_patterns:
        parser.error("Must specify target application or use --sample-config")
    
    # Initialize loader
    loader = FridaPatternLoader()
    
    # Load configuration
    if args.config:
        config = loader.load_config_file(args.config)
        loader.config = {**loader.default_config, **config}
        loader.load_patterns_from_config(config)
    else:
        loader.config = loader.default_config.copy()
    
    # Load simple JSON patterns
    if args.json_patterns:
        loader.load_patterns_from_json(args.json_patterns)
    
    # Override config with command line args
    if args.device:
        loader.config['device'] = args.device
    if args.attach:
        loader.config['spawn_mode'] = False
    if args.no_resume:
        loader.config['auto_resume'] = False
    if args.no_retval_decode:
        loader.config['enable_retval_decoding'] = False

    loader.config['max_string_length'] = args.max_string_length
    loader.config['log_level'] = args.log_level
    loader.config['max_matches'] = args.max_matches
    loader.config['hook_timeout'] = args.timeout
    loader.config['enable_stack_trace'] = args.stack_trace
    loader.config['enable_arg_dump'] = not args.no_arg_dump
    
    # Add patterns from command line
    if args.pattern:
        for pattern_arg in args.pattern:
            if ':' not in pattern_arg:
                parser.error(f"Invalid pattern format: {pattern_arg}. Use 'name:hex_pattern'")
            
            name, pattern = pattern_arg.split(':', 1)
            loader.add_pattern_from_args(name, pattern)
    
    if not loader.patterns:
        print("[!] No patterns loaded. Use -c config_file or -p name:pattern")
        return
    
    try:
        # Connect and start session
        print(f"[+] Connecting to {loader.config['device']} device...")
        loader.connect_device(loader.config['device'])
        
        print(f"[+] Starting session with target: {args.target}")
        loader.start_session(args.target, loader.config['spawn_mode'])
        
        # Load and run script
        print("[+] Loading Frida script with patterns...")
        loader.load_and_run_script()

        # sleep and resume
        time.sleep(2)
        loader.device.resume(loader.current_pid)
        
        print(f"[+] Loaded {len(loader.patterns)} patterns:")
        for name, pattern in loader.patterns.items():
            print(f"  • {name}: {pattern['description']}")
        
        if args.interactive:
            loader.run_interactive()
        else:
            print("[+] Press Ctrl+C to stop...")
            try:
                sys.stdin.read()
            except KeyboardInterrupt:
                pass
        
    except Exception as e:
        print(f"[!] Error: {e}")
        return 1
    
    finally:
        loader.cleanup()
    
    return 0

if __name__ == '__main__':
    sys.exit(main())