#!/usr/bin/env python3
"""
Frida Pattern Loader
Advanced pattern-based hooking tool for penetration testing
Supports config files, command-line patterns, interactive mode, and return value modification
"""

import argparse
import json
import sys
import time
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
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
            'device': 'usb',  # 'usb', 'local', or device ID
            'spawn_mode': True,  # True to spawn, False to attach
            'auto_resume': True,
            'log_level': 'INFO',
            'hook_timeout': 100,
            'max_matches': 100,
            'enable_stack_trace': False,
            'enable_arg_dump': True,
            'output_format': 'colored'  # 'colored', 'json', 'plain'
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
                        'on_leave': pattern_data.get('on_leave'),
                        'return_value': pattern_data.get('return_value'),
                        'return_type': pattern_data.get('return_type', 'auto')
                    }
    
    def load_patterns_from_json(self, json_path: str):
        """Load patterns from JSON file with extended fields including return value modification"""
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
            
            # Load patterns with extended fields
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
                    # Extended pattern configuration
                    allowed_fields = [
                        'pattern', 'regex', 'description', 'enabled',
                        'return_value', 'return_type', 'on_enter', 'on_leave'
                    ]
                    filtered_data = {}
                    
                    for field in allowed_fields:
                        if field in pattern_data:
                            filtered_data[field] = pattern_data[field]
                    
                    # Set defaults for missing required fields
                    self.patterns[pattern_name] = {
                        'pattern': filtered_data.get('pattern', ''),
                        'description': filtered_data.get('description', f'Pattern {pattern_name}'),
                        'regex': filtered_data.get('regex'),
                        'enabled': filtered_data.get('enabled', True),
                        'return_value': filtered_data.get('return_value'),
                        'return_type': filtered_data.get('return_type', 'auto'),
                        'on_enter': filtered_data.get('on_enter'),
                        'on_leave': filtered_data.get('on_leave')
                    }
                    
                    # Warn about ignored fields
                    ignored_fields = set(pattern_data.keys()) - set(allowed_fields)
                    if ignored_fields:
                        print(f"[!] Ignored unsupported fields in pattern '{pattern_name}': {', '.join(ignored_fields)}")
            
            print(f"[+] Loaded {len(self.patterns)} patterns from JSON: {json_path}")
            
        except Exception as e:
            raise Exception(f"Failed to load JSON pattern file: {e}")
    
    def add_pattern_from_args(self, name: str, pattern: str, description: str = None, 
                            return_value: Union[str, int, bool] = None, return_type: str = 'auto'):
        """Add pattern from command line arguments"""
        self.patterns[name] = {
            'pattern': pattern,
            'description': description or f'Pattern {name}',
            'enabled': True,
            'return_value': return_value,
            'return_type': return_type
        }
        
        return_info = f" (return: {return_value})" if return_value is not None else ""
        print(f"[+] Added pattern: {name} -> {pattern}{return_info}")
    
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
        """Generate the complete Frida script with patterns and return value modification"""
        
        # Enhanced base modular hooker script with return value modification
        base_script = """
/**
 * Modular Frida Script for Pattern-Based Method Hooking with Return Value Modification
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
            enabled: options.enabled !== false,
            returnValue: options.returnValue,
            returnType: options.returnType || 'auto'
        });
        this.log('DEBUG', `Added pattern: ${name} - ${cleanPattern}`);
        
        if (options.returnValue !== undefined) {
            this.log('INFO', `[${name}] Will modify return value to: ${options.returnValue} (type: ${options.returnType})`);
        }
    }

    convertReturnValue(value, type) {
        if (value === null || value === undefined) {
            return null;
        }

        try {
            switch (type.toLowerCase()) {
                case 'bool':
                case 'boolean':
                    if (typeof value === 'boolean') return value;
                    if (typeof value === 'string') {
                        return value.toLowerCase() === 'true' || value === '1';
                    }
                    return Boolean(value);
                    
                case 'int':
                case 'integer':
                case 'int32':
                    return parseInt(value);
                    
                case 'long':
                case 'int64':
                    return parseInt(value);
                    
                case 'float':
                case 'double':
                    return parseFloat(value);
                    
                case 'string':
                case 'str':
                    return String(value);
                    
                case 'ptr':
                case 'pointer':
                    if (typeof value === 'string') {
                        return ptr(value);
                    }
                    return value;
                    
                case 'null':
                    return ptr(0);
                    
                case 'auto':
                default:
                    // Auto-detect type
                    if (typeof value === 'boolean') return value;
                    if (typeof value === 'number') return value;
                    if (typeof value === 'string') {
                        // Try to parse as number
                        const num = parseFloat(value);
                        if (!isNaN(num) && isFinite(num)) {
                            return Number.isInteger(num) ? parseInt(value) : num;
                        }
                        
                        // Check for boolean strings
                        const lower = value.toLowerCase();
                        if (lower === 'true' || lower === 'false') {
                            return lower === 'true';
                        }
                        
                        // Check for pointer format
                        if (value.startsWith('0x') || value.match(/^[0-9a-fA-F]+$/)) {
                            try {
                                return ptr(value);
                            } catch (e) {
                                return value;
                            }
                        }
                        
                        return value;
                    }
                    return value;
            }
        } catch (e) {
            this.log('WARN', `Failed to convert return value '${value}' to type '${type}': ${e.message}`);
            return value;
        }
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

    defaultOnLeave(retval, context) {
        const patternConfig = this.patterns.get(context.patternName);
        
        // Log original return value
        this.log('INFO', `[${context.patternName}] Original return value: ${retval}`);
        
        // Check if we should modify the return value
        if (patternConfig && patternConfig.returnValue !== undefined && patternConfig.returnValue !== null) {
            const newRetval = this.convertReturnValue(patternConfig.returnValue, patternConfig.returnType);
            retval.replace(newRetval);
            
            this.log('INFO', `[${context.patternName}] *** MODIFIED return value to: ${newRetval} (type: ${patternConfig.returnType}) ***`);
        }
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

            let hookInfo = `[${patternName}] Hooked method at ${address}`;
            if (patternConfig.returnValue !== undefined) {
                hookInfo += ` (will return: ${patternConfig.returnValue})`;
            }
            this.log('INFO', hookInfo);
            
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
            patternsWithReturnMod: Array.from(this.patterns.values()).filter(p => p.returnValue !== undefined).length,
            patterns: Object.fromEntries(this.patterns)
        };
    }

    // Interactive functions for return value modification
    setReturnValue(patternName, value, type = 'auto') {
        const pattern = this.patterns.get(patternName);
        if (!pattern) {
            this.log('ERROR', `Pattern '${patternName}' not found`);
            return false;
        }
        
        pattern.returnValue = value;
        pattern.returnType = type;
        this.log('INFO', `Set return value for '${patternName}' to: ${value} (type: ${type})`);
        return true;
    }

    clearReturnValue(patternName) {
        const pattern = this.patterns.get(patternName);
        if (!pattern) {
            this.log('ERROR', `Pattern '${patternName}' not found`);
            return false;
        }
        
        pattern.returnValue = undefined;
        this.log('INFO', `Cleared return value modification for '${patternName}'`);
        return true;
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
globalThis.setReturnValue = hooker.setReturnValue.bind(hooker);
globalThis.clearReturnValue = hooker.clearReturnValue.bind(hooker);

// Start hooking
initializeHooking();
        """
        
        # Generate hooker configuration
        hooker_config = {
            'logLevel': self.config.get('log_level', 'INFO'),
            'hookTimeout': self.config.get('hook_timeout', 100),
            'maxMatches': self.config.get('max_matches', 100),
            'enableStackTrace': self.config.get('enable_stack_trace', False),
            'enableArgDump': self.config.get('enable_arg_dump', True)
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
            
            # Add return value modification options
            if pattern_data.get('return_value') is not None:
                options['returnValue'] = pattern_data['return_value']
                options['returnType'] = pattern_data.get('return_type', 'auto')
            
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
        """Run in interactive mode with return value modification commands"""
        print("\n[+] Interactive mode - Available commands:")
        print("  stats        - Show hooking statistics")
        print("  patterns     - List loaded patterns")
        print("  search       - Re-run pattern search")
        print("  unhook       - Remove all hooks")
        print("  setret <pattern> <value> [type] - Set return value for pattern")
        print("  clearret <pattern>              - Clear return value modification")
        print("  processes    - List device processes")
        print("  modules      - List loaded modules")
        print("  pid          - Show current PID")
        print("  help         - Show this help")
        print("  quit         - Exit")
        print()
        print("Return value types: auto, bool, int, long, float, string, ptr, null")
        print()
        
        try:
            while True:
                try:
                    cmd = input("frida-patterns> ").strip()
                    parts = cmd.split()
                    
                    if not parts:
                        continue
                        
                    cmd_name = parts[0].lower()
                    
                    if cmd_name in ['quit', 'exit', 'q']:
                        break
                    elif cmd_name == 'stats':
                        try:
                            result = self.script.exports_sync.get_stats()
                            print("Hook Statistics:", json.dumps(result, indent=2))
                        except AttributeError:
                            print("[!] Stats function not available. Script may not be fully loaded.")
                        except Exception as e:
                            print(f"[!] Error getting stats: {e}")
                    elif cmd_name == 'patterns':
                        print("\nLoaded Patterns:")
                        for name, pattern in self.patterns.items():
                            enabled = "✓" if pattern.get('enabled', True) else "✗"
                            regex_info = f" (regex: {pattern['regex']})" if pattern.get('regex') else ""
                            ret_info = ""
                            if pattern.get('return_value') is not None:
                                ret_info = f" [RETURN: {pattern['return_value']} ({pattern.get('return_type', 'auto')})]"
                            print(f"  {enabled} {name}: {pattern['pattern'][:50]}...{regex_info}{ret_info}")
                            print(f"    Description: {pattern.get('description', 'N/A')}")
                    elif cmd_name == 'search':
                        try:
                            self.script.exports_sync.search_patterns()
                        except AttributeError:
                            print("[!] Search function not available.")
                        except Exception as e:
                            print(f"[!] Error running search: {e}")
                    elif cmd_name == 'unhook':
                        try:
                            self.script.exports_sync.unhook_all()
                            print("[+] All hooks removed")
                        except AttributeError:
                            print("[!] Unhook function not available.")
                        except Exception as e:
                            print(f"[!] Error unhooking: {e}")
                    elif cmd_name == 'setret':
                        if len(parts) < 3:
                            print("[!] Usage: setret <pattern> <value> [type]")
                            continue
                        
                        pattern_name = parts[1]
                        value = parts[2]
                        ret_type = parts[3] if len(parts) > 3 else 'auto'
                        
                        # Convert value to appropriate Python type
                        if ret_type.lower() in ['bool', 'boolean']:
                            value = value.lower() in ['true', '1', 'yes']
                        elif ret_type.lower() in ['int', 'integer', 'int32', 'long', 'int64']:
                            try:
                                value = int(value)
                            except ValueError:
                                print(f"[!] Invalid integer value: {value}")
                                continue
                        elif ret_type.lower() in ['float', 'double']:
                            try:
                                value = float(value)
                            except ValueError:
                                print(f"[!] Invalid float value: {value}")
                                continue
                        
                        # Update local pattern configuration
                        if pattern_name in self.patterns:
                            self.patterns[pattern_name]['return_value'] = value
                            self.patterns[pattern_name]['return_type'] = ret_type
                            
                            # Update running script if available
                            try:
                                self.script.exports_sync.set_return_value(pattern_name, value, ret_type)
                                print(f"[+] Set return value for '{pattern_name}' to: {value} (type: {ret_type})")
                            except AttributeError:
                                print("[!] setReturnValue function not available in script.")
                            except Exception as e:
                                print(f"[!] Error setting return value: {e}")
                        else:
                            print(f"[!] Pattern '{pattern_name}' not found")
                    elif cmd_name == 'clearret':
                        if len(parts) < 2:
                            print("[!] Usage: clearret <pattern>")
                            continue
                        
                        pattern_name = parts[1]
                        
                        # Update local pattern configuration
                        if pattern_name in self.patterns:
                            self.patterns[pattern_name]['return_value'] = None
                            
                            # Update running script if available
                            try:
                                self.script.exports_sync.clear_return_value(pattern_name)
                                print(f"[+] Cleared return value modification for '{pattern_name}'")
                            except AttributeError:
                                print("[!] clearReturnValue function not available in script.")
                            except Exception as e:
                                print(f"[!] Error clearing return value: {e}")
                        else:
                            print(f"[!] Pattern '{pattern_name}' not found")
                    elif cmd_name == 'processes':
                        try:
                            processes = self.device.enumerate_processes()
                            print("\nRunning Processes:")
                            for proc in processes[:20]:  # Show first 20
                                print(f"  {proc.pid:>6}: {proc.name}")
                            if len(processes) > 20:
                                print(f"  ... and {len(processes) - 20} more")
                        except Exception as e:
                            print(f"[!] Error listing processes: {e}")
                    elif cmd_name == 'modules':
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
                    elif cmd_name == 'pid':
                        print(f"Current PID: {self.current_pid}")
                    elif cmd_name == 'help':
                        print("Available commands:")
                        print("  stats, patterns, search, unhook")
                        print("  setret <pattern> <value> [type] - Set return value")
                        print("  clearret <pattern> - Clear return value modification")
                        print("  processes, modules, pid, help, quit")
                        print("\nReturn value types: auto, bool, int, long, float, string, ptr, null")
                    elif cmd:
                        print(f"Unknown command: {cmd_name}. Type 'help' for available commands.")
                        
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
    """Create a sample configuration file with return value modification examples"""
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
                'enabled': True,
                'return_value': True,
                'return_type': 'bool'
            },
            'ssl_pinning_check': {
                'pattern': '?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 01 ?? ??',
                'regex': 'SSLSetSessionOption|SSLHandshake|SecTrustEvaluate',
                'description': 'SSL/TLS security validation methods - bypass by returning success',
                'enabled': True,
                'return_value': 0,
                'return_type': 'int'
            },
            'jailbreak_detection': {
                'pattern': '?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??',
                'regex': 'stat|access|fopen.*cydia|substrate',
                'description': 'Jailbreak detection patterns - return failure to hide jailbreak',
                'enabled': True,
                'return_value': -1,
                'return_type': 'int'
            },
            'license_check': {
                'pattern': 'ff 43 01 d1 fd 7b 02 a9 fd 83 00 91 f3 53 01 a9',
                'description': 'License validation - always return valid',
                'enabled': True,
                'return_value': True,
                'return_type': 'bool'
            },
            'biometric_auth': {
                'pattern': '?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??',
                'regex': 'LAContext|evaluatePolicy|canEvaluatePolicy',
                'description': 'Biometric authentication bypass',
                'enabled': True,
                'return_value': True,
                'return_type': 'bool'
            }
        }
    }
    
    return sample_config

def parse_return_value_arg(arg_str: str) -> tuple:
    """Parse return value argument in format 'value:type' or just 'value'"""
    if ':' in arg_str:
        value_str, ret_type = arg_str.rsplit(':', 1)
    else:
        value_str, ret_type = arg_str, 'auto'
    
    # Auto-convert common values
    if ret_type.lower() == 'auto':
        if value_str.lower() in ['true', 'false']:
            return value_str.lower() == 'true', 'bool'
        elif value_str.lower() == 'null':
            return None, 'null'
        elif value_str.isdigit() or (value_str.startswith('-') and value_str[1:].isdigit()):
            return int(value_str), 'int'
        elif '.' in value_str:
            try:
                return float(value_str), 'float'
            except ValueError:
                return value_str, 'string'
        elif value_str.startswith('0x') or all(c in '0123456789abcdefABCDEF' for c in value_str):
            return value_str, 'ptr'
        else:
            return value_str, 'string'
    else:
        # Explicit type conversion
        if ret_type.lower() in ['bool', 'boolean']:
            return value_str.lower() in ['true', '1', 'yes'], ret_type
        elif ret_type.lower() in ['int', 'integer', 'int32', 'long', 'int64']:
            return int(value_str), ret_type
        elif ret_type.lower() in ['float', 'double']:
            return float(value_str), ret_type
        elif ret_type.lower() == 'null':
            return None, ret_type
        else:
            return value_str, ret_type

def main():
    show_banner()
    parser = argparse.ArgumentParser(
        description='Frida Pattern Loader - Advanced pattern-based hooking with return value modification',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Load patterns from config file with return value modifications
  python frida_loader.py -c patterns.yml -t com.example.app
  
  # Load JSON patterns with return value modifications
  python frida_loader.py -j patterns.json -t com.example.app
  
  # Add pattern with return value modification via CLI
  python frida_loader.py -t com.example.app -p "bypass:a1 18 00 f0:true:bool"
  python frida_loader.py -t com.example.app -p "check:ff 43 01 d1:-1:int"
  python frida_loader.py -t com.example.app -p "auth:?? ?? ?? ??:0x1:ptr"
  
  # Multiple patterns with different return types
  python frida_loader.py -t app -p "ssl:00 01 ?? ??:0" -p "jail:ff ff:false:bool"
  
  # Return value format: value:type (e.g., true:bool, -1:int, 0x0:ptr)
  # Supported types: auto, bool, int, long, float, string, ptr, null
  
  # Generate sample config with return value examples
  python frida_loader.py --sample-config > advanced_patterns.yml
        """
    )
    
    parser.add_argument('-c', '--config', type=str, help='Configuration file (YAML/JSON)')
    parser.add_argument('-j', '--json-patterns', type=str, help='JSON pattern file with return value modifications')
    parser.add_argument('-t', '--target', type=str, help='Target application (bundle ID or process name)')
    parser.add_argument('-d', '--device', type=str, default='usb', help='Device type: usb, local, or device ID')
    parser.add_argument('-p', '--pattern', action='append', 
                       help='Pattern in format "name:hex_pattern[:return_value[:return_type]]"')
    parser.add_argument('-r', '--return-value', action='append', nargs=2, metavar=('PATTERN', 'VALUE:TYPE'),
                       help='Set return value for existing pattern (e.g., -r ssl_check "true:bool")')
    parser.add_argument('--attach', action='store_true', help='Attach mode (default: spawn)')
    parser.add_argument('--no-resume', action='store_true', help='Don\'t auto-resume spawned process')
    parser.add_argument('-i', '--interactive', action='store_true', help='Run in interactive mode')
    parser.add_argument('--sample-config', action='store_true', help='Generate sample configuration file')
    parser.add_argument('--log-level', choices=['ERROR', 'WARN', 'INFO', 'DEBUG'], default='INFO')
    parser.add_argument('--max-matches', type=int, default=100, help='Maximum pattern matches')
    parser.add_argument('--timeout', type=int, default=100, help='Hook timeout in milliseconds')
    parser.add_argument('--stack-trace', action='store_true', help='Enable stack traces')
    parser.add_argument('--no-arg-dump', action='store_true', help='Disable argument dumping')
    
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
    
    # Load JSON patterns (now supports return value modification)
    if args.json_patterns:
        loader.load_patterns_from_json(args.json_patterns)
    
    # Override config with command line args
    if args.device:
        loader.config['device'] = args.device
    if args.attach:
        loader.config['spawn_mode'] = False
    if args.no_resume:
        loader.config['auto_resume'] = False
    
    loader.config['log_level'] = args.log_level
    loader.config['max_matches'] = args.max_matches
    loader.config['hook_timeout'] = args.timeout
    loader.config['enable_stack_trace'] = args.stack_trace
    loader.config['enable_arg_dump'] = not args.no_arg_dump
    
    # Add patterns from command line with return value support
    if args.pattern:
        for pattern_arg in args.pattern:
            parts = pattern_arg.split(':')
            
            if len(parts) < 2:
                parser.error(f"Invalid pattern format: {pattern_arg}. Use 'name:hex_pattern[:return_value[:return_type]]'")
            
            name = parts[0]
            pattern = parts[1]
            
            return_value = None
            return_type = 'auto'
            
            if len(parts) >= 3:
                return_value_str = ':'.join(parts[2:])  # Handle values with colons
                return_value, return_type = parse_return_value_arg(return_value_str)
            
            loader.add_pattern_from_args(name, pattern, return_value=return_value, return_type=return_type)
    
    # Set return values for existing patterns
    if args.return_value:
        for pattern_name, value_type_str in args.return_value:
            if pattern_name in loader.patterns:
                return_value, return_type = parse_return_value_arg(value_type_str)
                loader.patterns[pattern_name]['return_value'] = return_value
                loader.patterns[pattern_name]['return_type'] = return_type
                print(f"[+] Set return value for '{pattern_name}': {return_value} ({return_type})")
            else:
                print(f"[!] Pattern '{pattern_name}' not found for return value setting")
    
    if not loader.patterns:
        print("[!] No patterns loaded. Use -c config_file, -j json_file, or -p name:pattern")
        return
    
    try:
        # Connect and start session
        print(f"[+] Connecting to {loader.config['device']} device...")
        loader.connect_device(loader.config['device'])
        
        print(f"[+] Starting session with target: {args.target}")
        loader.start_session(args.target, loader.config['spawn_mode'])
        
        # Load and run script
        print("[+] Loading Frida script with patterns and return value modifications...")
        loader.load_and_run_script()

        # sleep and resume
        time.sleep(2)
        loader.device.resume(loader.current_pid)
        
        print(f"[+] Loaded {len(loader.patterns)} patterns:")
        for name, pattern in loader.patterns.items():
            ret_info = ""
            if pattern.get('return_value') is not None:
                ret_info = f" [RETURNS: {pattern['return_value']} ({pattern.get('return_type', 'auto')})]"
            print(f"  • {name}: {pattern['description']}{ret_info}")
        
        # Count patterns with return value modifications
        return_mod_count = len([p for p in loader.patterns.values() if p.get('return_value') is not None])
        if return_mod_count > 0:
            print(f"\n[+] {return_mod_count} patterns configured with return value modifications")
        
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