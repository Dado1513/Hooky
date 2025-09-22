/**
 * Modular Frida Script for Pattern-Based Method Hooking
 * Designed for penetration testing and reverse engineering
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

    /**
     * Add pattern with metadata
     * @param {string} name - Pattern identifier
     * @param {string} pattern - Hex pattern (spaces optional)
     * @param {Object} options - Hook options
     */
    addPattern(name, pattern, options = {}) {
        const cleanPattern = pattern.replace(/\s+/g, ' ').trim();
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

    /**
     * Default onEnter handler
     */
    defaultOnEnter(args, context) {
        this.log('INFO', `[${context.patternName}] Method called at ${context.address}`);
        
        if (this.config.enableArgDump) {
            // TODO FIX HERE
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
                    
                    // Try to read as string
                    if (arg && !arg.isNull()) {
                        try {
                            const str = Memory.readUtf8String(arg, 100);
                            if (str && str.length > 0 && /^[\x20-\x7E]*$/.test(str)) {
                                argInfo += ` ("${str}")`;
                            }
                        } catch (e) {
                            // Try as pointer
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

    /**
     * Default onLeave handler
     */
    defaultOnLeave(retval, context) {
        this.log('INFO', `[${context.patternName}] Return value: ${retval}`);
    }

    /**
     * Hook a specific method by address
     */
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

    /**
     * Search for patterns in memory ranges
     */
    searchPatterns(rangeFilter = null) {
        this.log('INFO', 'Starting pattern search...');
        
        const ranges = Process.enumerateRangesSync('r-x').filter(range => {
            if (rangeFilter) {
                return rangeFilter(range);
            }
            return range.size > 0x1000; // Skip small ranges
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

                        // Apply regex filter if specified
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

    /**
     * Remove all hooks
     */
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

    /**
     * Get statistics
     */
    getStats() {
        return {
            totalPatterns: this.patterns.size,
            enabledPatterns: Array.from(this.patterns.values()).filter(p => p.enabled).length,
            activeHooks: this.hooks.size,
            patterns: Object.fromEntries(this.patterns)
        };
    }
}

// Export for use
const hooker = new PatternHooker({
    logLevel: 'INFO',
    enableStackTrace: false,
    enableArgDump: true,
    maxMatches: 100
});

// Example usage patterns
function setupCommonPatterns() {
    // Password-related patterns



hooker.addPattern('<set_name>',
    '<set_pattern>',
    {
        description: '<set description>',
        onEnter: function(args, context) {
            console.log('<set_name> Hooked!');
            hooker.defaultOnEnter.call(this, args, context);
        },
        
        onLeave: function(retval, context) {
            const returnValue = ObjC.Object(retval).toString();
            console.log(`<set_name_return_value>: ${returnValue}`);
            hooker.defaultOnLeave.call(this, retval, context);

        }
    }
);


  
}

// Main execution - No Java.perform needed for native/iOS
function initializeHooker() {
    setupCommonPatterns();
    
    setTimeout(() => {
        const matches = hooker.searchPatterns();
        console.log(`[SUMMARY] Setup complete. Found ${matches} matches.`);
        console.log('[STATS]', JSON.stringify(hooker.getStats(), null, 2));
    }, hooker.config.hookTimeout);
}

// Auto-initialize
initializeHooker();

// Global functions for interactive use
globalThis.hooker = hooker;
globalThis.addPattern = hooker.addPattern.bind(hooker);
globalThis.searchPatterns = hooker.searchPatterns.bind(hooker);
globalThis.unhookAll = hooker.unhookAll.bind(hooker);
globalThis.getStats = hooker.getStats.bind(hooker);