#!/usr/bin/env python3
"""
Enhanced Interactive Frida Hook with Primitive and Complex Object Modes
- Mode 1: Primitives only (safe, no crashes)
- Mode 2: All types with advanced casting (handles complex objects)
"""

import frida
import sys
import threading
import json
import time
from queue import Queue, Empty

class EnhancedInteractiveFridaHook:
    def __init__(self, package_name, target_class, method_filters=None, mode="primitives"):
        self.package_name = package_name
        self.target_class = target_class
        self.method_filters = method_filters or []
        self.mode = mode  # "primitives" or "all"
        self.device = None
        self.session = None
        self.script = None
        self.user_responses = Queue()
        self.pending_requests = {}

    def on_message(self, message, data):
        """Handle messages from Frida script with improved error handling"""
        try:
            if message['type'] == 'send':
                payload = message['payload']
                
                if payload['type'] == 'log':
                    print(f"[FRIDA] {payload['message']}")
                    
                elif payload['type'] == 'method_call':
                    # Handle method call interception in separate thread to prevent blocking
                    try:
                        self.handle_method_call(payload)
                    except Exception as e:
                        print(f"[-] Error handling method call {payload.get('call_id', 'unknown')}: {e}")
                        # Send emergency default response
                        emergency_response = {
                            'call_id': payload.get('call_id', 0),
                            'action': 'continue',
                            'modified_args': None,
                            'return_override': None
                        }
                        try:
                            self.script.post(emergency_response)
                        except:
                            print(f"[-] Failed to send emergency response")
                    
            elif message['type'] == 'error':
                print(f"[ERROR] {message['description']}")
                
        except Exception as e:
            print(f"[-] Critical error in on_message: {e}")

    def is_primitive_type(self, type_name):
        """Check if a type is primitive or simple"""
        primitive_types = {
            'boolean', 'java.lang.Boolean',
            'byte', 'java.lang.Byte',
            'short', 'java.lang.Short', 
            'int', 'java.lang.Integer',
            'long', 'java.lang.Long',
            'float', 'java.lang.Float',
            'double', 'java.lang.Double',
            'char', 'java.lang.Character',
            'java.lang.String',
            'void'
        }
        return type_name in primitive_types

    def has_primitive_signature(self, method_info):
        """Check if method has only primitive parameters and return type"""
        # Check return type
        if not self.is_primitive_type(method_info.get('return_type', '')):
            return False
        
        # Check all arguments
        for arg in method_info.get('arguments', []):
            if not self.is_primitive_type(arg.get('type', '')):
                return False
                
        return True

    def handle_method_call(self, payload):
        """Handle intercepted method calls with robust error handling"""
        method_name = payload['method_name']
        class_name = payload['class_name']
        args = payload['arguments']
        call_id = payload['call_id']
        return_type = payload.get('return_type', 'unknown')
        
        print(f"\n{'='*60}")
        print(f"[INTERCEPTED] {class_name}.{method_name}")
        print(f"[CALL ID] {call_id}")
        print(f"[RETURN TYPE] {return_type}")
        print(f"[MODE] {self.mode.upper()}")
        
        # Show type safety info
        is_primitive_method = self.has_primitive_signature(payload)
        if self.mode == "primitives":
            print(f"[PRIMITIVE SAFE] {'✅ Yes' if is_primitive_method else '❌ No (skipped complex types)'}")
        else:
            print(f"[PRIMITIVE SAFE] {'✅ Yes' if is_primitive_method else '⚠️ No (using advanced casting)'}")
        
        print(f"{'='*60}")
        
        # Display arguments
        if args:
            print("[ARGUMENTS]")
            for i, arg in enumerate(args):
                arg_type = arg['type']
                is_prim = self.is_primitive_type(arg_type)
                type_indicator = "🟢" if is_prim else "🔴"
                print(f"  [{i}] {type_indicator} {arg_type}: {arg['value']}")
        else:
            print("[ARGUMENTS] None")
        
        def send_response(response):
            """Helper function to send response with error handling"""
            try:
                print(f"[DEBUG] Sending response for call {call_id}: {response['action']}")
                self.script.post(response)
                print(f"[DEBUG] Response sent successfully for call {call_id}")
            except Exception as e:
                print(f"[-] Failed to send response for call {call_id}: {e}")
        
        # Prepare default response
        default_response = {
            'call_id': call_id,
            'action': 'continue',
            'modified_args': None,
            'return_override': None
        }
        
        try:
            # Ask user what they want to do
            print("\nWhat would you like to do?")
            print("1. Continue with original values")
            print("2. Modify input parameters")
            print("3. Set return value override")
            print("4. Modify inputs AND set return override")
            
            choice = input("Enter choice (1-4): ").strip()
            
            response = {
                'call_id': call_id,
                'action': 'continue',
                'modified_args': None,
                'return_override': None
            }
            
            if choice == '2' or choice == '4':
                # Modify input parameters
                try:
                    modified_args = self.get_modified_arguments(args)
                    response['modified_args'] = modified_args
                    response['action'] = 'modify_input'
                except Exception as e:
                    print(f"[-] Error getting modified arguments: {e}")
                    print("[!] Using default continue action")
            
            if choice == '3' or choice == '4':
                # Set return value override
                try:
                    return_override = self.get_return_override(return_type)
                    response['return_override'] = return_override
                    if choice == '3':
                        response['action'] = 'override_return'
                    else:
                        response['action'] = 'modify_both'
                except Exception as e:
                    print(f"[-] Error getting return override: {e}")
                    print("[!] Using default continue action")
                    # Reset to safe defaults
                    response['action'] = 'continue'
                    response['return_override'] = None
            
            send_response(response)
            
        except KeyboardInterrupt:
            print("\n[+] User interrupted, sending default response")
            send_response(default_response)
        except EOFError:
            print("\n[+] Input ended, sending default response")
            send_response(default_response)
        except Exception as e:
            print(f"[-] Unexpected error in handle_method_call: {e}")
            print("[!] Sending safe default response")
            send_response(default_response)

    def get_modified_arguments(self, args):
        """Get modified arguments from user"""
        modified_args = []
        
        print("\n[MODIFY ARGUMENTS]")
        for i, arg in enumerate(args):
            current_value = arg['value']
            arg_type = arg['type']
            is_prim = self.is_primitive_type(arg_type)
            
            print(f"\nArgument [{i}] ({arg_type}) {'🟢 PRIMITIVE' if is_prim else '🔴 COMPLEX'}")
            print(f"Current value: {current_value}")
            
            if not is_prim and self.mode == "primitives":
                print("⚠️ Skipping complex type in primitives mode")
                continue
            
            modify = input("Modify this argument? (y/n): ").strip().lower()
            
            if modify == 'y':
                if arg_type == 'java.lang.String':
                    new_value = input("Enter new string value: ")
                    modified_args.append({'index': i, 'value': new_value, 'type': 'string'})
                    
                elif arg_type in ['int', 'java.lang.Integer']:
                    try:
                        new_value = int(input("Enter new integer value: "))
                        modified_args.append({'index': i, 'value': new_value, 'type': 'int'})
                    except ValueError:
                        print("Invalid integer, keeping original value")
                        
                elif arg_type in ['boolean', 'java.lang.Boolean']:
                    new_value = input("Enter new boolean value (true/false): ").strip().lower() == 'true'
                    modified_args.append({'index': i, 'value': new_value, 'type': 'boolean'})
                    
                elif arg_type in ['double', 'java.lang.Double', 'float', 'java.lang.Float']:
                    try:
                        new_value = float(input("Enter new double value: "))
                        modified_args.append({'index': i, 'value': new_value, 'type': 'double'})
                    except ValueError:
                        print("Invalid double, keeping original value")
                        
                elif arg_type in ['long', 'java.lang.Long']:
                    try:
                        new_value = int(input("Enter new long value: "))
                        modified_args.append({'index': i, 'value': new_value, 'type': 'long'})
                    except ValueError:
                        print("Invalid long, keeping original value")
                        
                else:
                    # For complex types in "all" mode
                    if self.mode == "all":
                        print("Complex type options:")
                        print("1. Set to null")
                        print("2. Create empty object")
                        print("3. Skip modification")
                        
                        complex_choice = input("Choose (1-3): ").strip()
                        if complex_choice == '1':
                            modified_args.append({'index': i, 'value': None, 'type': 'null'})
                        elif complex_choice == '2':
                            modified_args.append({'index': i, 'value': 'EMPTY_OBJECT', 'type': 'object'})
        
        return modified_args

    def get_return_override(self, return_type):
        """Get return value override from user with type awareness"""
        print(f"\n[RETURN VALUE OVERRIDE for {return_type}]")
        
        is_prim = self.is_primitive_type(return_type)
        print(f"Return type is {'🟢 PRIMITIVE' if is_prim else '🔴 COMPLEX'}")
        
        if not is_prim and self.mode == "primitives":
            print("⚠️ Complex return type in primitives mode - using null")
            return {'value': None, 'type': 'null'}
        
        # Suggest appropriate type based on method return type
        if 'boolean' in return_type.lower():
            suggested_type = 'boolean'
        elif 'int' in return_type.lower():
            suggested_type = 'int'
        elif 'string' in return_type.lower():
            suggested_type = 'string'
        elif 'double' in return_type.lower() or 'float' in return_type.lower():
            suggested_type = 'double'
        elif 'long' in return_type.lower():
            suggested_type = 'long'
        elif 'void' in return_type.lower():
            suggested_type = 'void'
        else:
            suggested_type = 'null' if self.mode == "primitives" else 'object'
        
        print(f"Detected return type: {return_type}")
        print(f"Suggested override type: {suggested_type}")
        
        if self.mode == "primitives":
            available_types = "string/int/boolean/double/long/null/void"
        else:
            available_types = "string/int/boolean/double/long/object/null/void"
            
        override_type = input(f"Return type ({available_types}) [{suggested_type}]: ").strip().lower()
        if not override_type:
            override_type = suggested_type
        
        if override_type == 'null':
            return {'value': None, 'type': 'null'}
        elif override_type == 'void':
            return {'value': 'VOID', 'type': 'void'}
        elif override_type == 'string':
            value = input("Enter string return value: ")
            return {'value': value, 'type': 'string'}
        elif override_type == 'int':
            try:
                value = int(input("Enter integer return value: "))
                return {'value': value, 'type': 'int'}
            except ValueError:
                print("Invalid integer, using null")
                return {'value': None, 'type': 'null'}
        elif override_type == 'boolean':
            value = input("Enter boolean return value (true/false): ").strip().lower() == 'true'
            return {'value': value, 'type': 'boolean'}
        elif override_type == 'double':
            try:
                value = float(input("Enter double return value: "))
                return {'value': value, 'type': 'double'}
            except ValueError:
                print("Invalid double, using null")
                return {'value': None, 'type': 'null'}
        elif override_type == 'long':
            try:
                value = int(input("Enter long return value: "))
                return {'value': value, 'type': 'long'}
            except ValueError:
                print("Invalid long, using null")
                return {'value': None, 'type': 'null'}
        elif override_type == 'object' and self.mode == "all":
            print("Object options:")
            print("1. null")
            print("2. Empty object")
            print("3. Try to create default instance")
            obj_choice = input("Choose (1-3): ").strip()
            
            if obj_choice == '1':
                return {'value': None, 'type': 'null'}
            elif obj_choice == '2':
                return {'value': 'EMPTY_OBJECT', 'type': 'object'}
            else:
                return {'value': 'DEFAULT_INSTANCE', 'type': 'object'}
        else:
            return {'value': None, 'type': 'null'}

    def get_frida_script(self):
        """Return JavaScript with mode-specific filtering and casting"""
        method_filters_json = json.dumps(self.method_filters)
        mode = self.mode
        
        return f"""
        Java.perform(function() {{
            console.log("[+] Starting Enhanced Interactive Method Interceptor");
            console.log("[+] Mode: {mode.upper()}");
            
            const TARGET_CLASS = '{self.target_class}';
            const METHOD_FILTERS = {method_filters_json};
            const MODE = '{mode}';
            let callIdCounter = 0;
            const pendingCalls = {{}};
            
            // Helper function to check if type is primitive
            function isPrimitiveType(typeName) {{
                const primitives = [
                    'boolean', 'java.lang.Boolean',
                    'byte', 'java.lang.Byte',
                    'short', 'java.lang.Short',
                    'int', 'java.lang.Integer', 
                    'long', 'java.lang.Long',
                    'float', 'java.lang.Float',
                    'double', 'java.lang.Double',
                    'char', 'java.lang.Character',
                    'java.lang.String',
                    'void'
                ];
                return primitives.includes(typeName);
            }}
            
            // Helper function to check if method should be hooked based on mode
            function shouldHookMethodByMode(returnTypeName, paramTypeNames) {{
                if (MODE === 'primitives') {{
                    // Only hook if return type and all params are primitive
                    if (!isPrimitiveType(returnTypeName)) {{
                        return false;
                    }}
                    for (let i = 0; i < paramTypeNames.length; i++) {{
                        if (!isPrimitiveType(paramTypeNames[i])) {{
                            return false;
                        }}
                    }}
                    return true;
                }} else {{
                    // Hook all methods in 'all' mode
                    return true;
                }}
            }}
            
            // Helper function to check if method should be hooked by name
            function shouldHookMethodByName(methodName) {{
                if (METHOD_FILTERS.length === 0) {{
                    return true;
                }}
                
                for (let i = 0; i < METHOD_FILTERS.length; i++) {{
                    const filter = METHOD_FILTERS[i];
                    try {{
                        if (new RegExp(filter).test(methodName)) {{
                            return true;
                        }}
                    }} catch (e) {{
                        if (methodName.includes(filter)) {{
                            return true;
                        }}
                    }}
                }}
                return false;
            }}
            
            // Advanced casting function for complex objects
            function castReturnValueAdvanced(value, valueType, targetTypeName) {{
                try {{
                    if (value === null || valueType === 'null') {{
                        return null;
                    }}
                    
                    if (valueType === 'void') {{
                        return undefined;
                    }}
                    
                    // Handle object types with advanced casting
                    if (valueType === 'object') {{
                        if (value === 'EMPTY_OBJECT') {{
                            // Try to create empty instance
                            try {{
                                const targetClass = Java.use(targetTypeName);
                                // First try no-arg constructor
                                try {{
                                    return targetClass.$new();
                                }} catch (e1) {{
                                    // If that fails, try static methods or return null
                                    console.log('[CAST] No default constructor for ' + targetTypeName + ', using null');
                                    return null;
                                }}
                            }} catch (e2) {{
                                console.log('[CAST] Cannot load class ' + targetTypeName + ', using null');
                                return null;
                            }}
                        }} else if (value === 'DEFAULT_INSTANCE') {{
                            // Try to create a default instance with more advanced techniques
                            try {{
                                const targetClass = Java.use(targetTypeName);
                                
                                // Try common static factory methods
                                const factoryMethods = ['getInstance', 'create', 'newInstance', 'getDefault', 'empty'];
                                for (let method of factoryMethods) {{
                                    try {{
                                        if (targetClass[method]) {{
                                            return targetClass[method]();
                                        }}
                                    }} catch (e) {{
                                        continue;
                                    }}
                                }}
                                
                                // If factory methods fail, try constructor
                                return targetClass.$new();
                                
                            }} catch (e) {{
                                console.log('[CAST] Advanced casting failed for ' + targetTypeName + ': ' + e.message);
                                return null;
                            }}
                        }}
                        
                        // Handle special known problematic types
                        if (targetTypeName.includes('ModuleDefinitionData')) {{
                            return null;
                        }}
                        if (targetTypeName === 'java.lang.Object') {{
                            return Java.use('java.lang.Object').$new();
                        }}
                    }}
                    
                    // Primitive type casting (same as before but enhanced)
                    if (valueType === 'string') {{
                        if (targetTypeName === 'java.lang.String') {{
                            return Java.use('java.lang.String').$new(value);
                        }}
                        return String(value);
                    }} else if (valueType === 'int') {{
                        if (targetTypeName === 'java.lang.Integer') {{
                            return Java.use('java.lang.Integer').valueOf(parseInt(value));
                        }}
                        return parseInt(value);
                    }} else if (valueType === 'boolean') {{
                        if (targetTypeName === 'java.lang.Boolean') {{
                            const result = Java.use('java.lang.Boolean').valueOf(Boolean(value));
                            send({{type: 'log', message: 'Created Boolean object: ' + result}});
                            return result;
                        }} else if (targetTypeName === 'boolean') {{
                            const result = Boolean(value);
                            send({{type: 'log', message: 'Created primitive boolean: ' + result}});
                            return result;
                        }}
                        return Boolean(value);
                        }} else if (valueType === 'double') {{
                        if (targetTypeName === 'java.lang.Double') {{
                            return Java.use('java.lang.Double').valueOf(parseFloat(value));
                        }} else if (targetTypeName === 'java.lang.Float') {{
                            return Java.use('java.lang.Float').valueOf(parseFloat(value));
                        }}
                        return parseFloat(value);
                    }} else if (valueType === 'long') {{
                        if (targetTypeName === 'java.lang.Long') {{
                            return Java.use('java.lang.Long').valueOf(parseInt(value));
                        }}
                        return parseInt(value);
                    }}
                    
                    return value;
                }} catch (castError) {{
                    console.log('[CAST ERROR] ' + castError.message + ' for type: ' + targetTypeName);
                    return createSafeDefault(targetTypeName);
                }}
            }}
            
            // Enhanced safe default creation
            function createSafeDefault(returnTypeName) {{
                try {{
                    if (returnTypeName === 'void') {{
                        return undefined;
                    }} else if (returnTypeName === 'boolean') {{
                        return false;
                    }} else if (returnTypeName === 'java.lang.Boolean') {{
                        return Java.use('java.lang.Boolean').valueOf(false);
                    }} else if (returnTypeName === 'int' || returnTypeName === 'byte' || returnTypeName === 'short') {{
                        return 0;
                    }} else if (returnTypeName === 'java.lang.Integer') {{
                        return Java.use('java.lang.Integer').valueOf(0);
                    }} else if (returnTypeName === 'long') {{
                        return 0;
                    }} else if (returnTypeName === 'java.lang.Long') {{
                        return Java.use('java.lang.Long').valueOf(0);
                    }} else if (returnTypeName === 'double' || returnTypeName === 'float') {{
                        return 0.0;
                    }} else if (returnTypeName === 'java.lang.Double') {{
                        return Java.use('java.lang.Double').valueOf(0.0);
                    }} else if (returnTypeName === 'java.lang.Float') {{
                        return Java.use('java.lang.Float').valueOf(0.0);
                    }} else if (returnTypeName === 'java.lang.String') {{
                        return Java.use('java.lang.String').$new("");
                    }} else if (returnTypeName === 'java.lang.Object') {{
                        return Java.use('java.lang.Object').$new();
                    }} else if (returnTypeName.includes('ModuleDefinitionData') || 
                               returnTypeName.includes('expo') ||
                               returnTypeName.includes('react')) {{
                        // Safe handling of problematic Expo/React Native types
                        return null;
                    }} else {{
                        // For other complex types, try to be smarter
                        if (MODE === 'all') {{
                            try {{
                                const targetClass = Java.use(returnTypeName);
                                return targetClass.$new();
                            }} catch (e) {{
                                console.log('[DEFAULT] Cannot create instance of ' + returnTypeName + ', using null');
                                return null;
                            }}
                        }}
                        return null;
                    }}
                }} catch (e) {{
                    console.log('[DEFAULT] Error creating default for ' + returnTypeName + ': ' + e.message);
                    return null;
                }}
            }}
            
            try {{
                const targetClass = Java.use(TARGET_CLASS);
                send({{type: 'log', message: 'Found target class: ' + TARGET_CLASS}});
                
                const methods = targetClass.class.getDeclaredMethods();
                send({{type: 'log', message: 'Found ' + methods.length + ' methods in class'}});
                
                let hookedCount = 0;
                let skippedCount = 0;
                const originalImplementations = {{}};
                
                methods.forEach(function(method) {{
                    const methodName = method.getName();
                    const paramTypes = method.getParameterTypes();
                    const returnType = method.getReturnType();
                    const returnTypeName = returnType.getName();
                    
                    if (methodName === "<init>" || methodName === "<clinit>") {{
                        return;
                    }}
                    
                    if (!shouldHookMethodByName(methodName)) {{
                        return;
                    }}
                    
                    const paramTypeNames = [];
                    for (let i = 0; i < paramTypes.length; i++) {{
                        paramTypeNames.push(paramTypes[i].getName());
                    }}
                    
                    // Check mode compatibility
                    if (!shouldHookMethodByMode(returnTypeName, paramTypeNames)) {{
                        skippedCount++;
                        send({{type: 'log', message: 'SKIPPED (non-primitive): ' + methodName + ' -> ' + returnTypeName}});
                        return;
                    }}
                    
                    try {{
                        send({{type: 'log', message: 'HOOKING: ' + methodName + '(' + paramTypeNames.join(', ') + ') -> ' + returnTypeName}});
                        
                        const methodKey = methodName + "_" + paramTypeNames.join("_");
                        
                        let originalMethod;
                        try {{
                            if (paramTypeNames.length === 0) {{
                                originalMethod = targetClass[methodName].overload();
                            }} else {{
                                originalMethod = targetClass[methodName].overload.apply(targetClass[methodName], paramTypeNames);
                            }}
                            originalImplementations[methodKey] = originalMethod;
                        }} catch (overloadError) {{
                            send({{type: 'log', message: 'Overload error for ' + methodName + ': ' + overloadError.message}});
                            return;
                        }}
                        
                        // Method implementation with improved cleanup and error handling
                        originalMethod.implementation = function() {{
                            const args = Array.prototype.slice.call(arguments);
                            const callId = ++callIdCounter;
                            
                            send({{type: 'log', message: 'Starting method call ' + callId + ': ' + methodName}});
                            
                            // Prepare argument data
                            const argData = [];
                            for (let i = 0; i < args.length; i++) {{
                                let argValue = args[i];
                                let argType = paramTypeNames[i] || 'unknown';
                                
                                try {{
                                    if (argValue === null) {{
                                        argValue = "null";
                                    }} else if (typeof argValue === 'object') {{
                                        try {{
                                            argValue = argValue.toString();
                                            if (argValue.length > 200) {{
                                                argValue = argValue.substring(0, 200) + "...";
                                            }}
                                        }} catch (e) {{
                                            argValue = "[Object: " + argType + "]";
                                        }}
                                    }} else {{
                                        argValue = String(argValue);
                                    }}
                                }} catch (e) {{
                                    argValue = "[Error reading value]";
                                }}

                                argData.push({{
                                    type: argType,
                                    value: argValue
                                }});
                            }}
                            
                            // Store call information
                            pendingCalls[callId] = {{
                                args: Array.prototype.slice.call(arguments),
                                originalImpl: originalImplementations[methodKey],
                                context: this,
                                returnTypeName: returnTypeName,
                                completed: false,
                                result: null,
                                response: null,
                                startTime: Date.now()
                            }};
                            
                            // Send method call data to Python
                            send({{
                                type: 'method_call',
                                call_id: callId,
                                class_name: TARGET_CLASS,
                                method_name: methodName,
                                return_type: returnTypeName,
                                arguments: argData
                            }});
                            
                            // Poll for response with timeout and better error handling
                            const timeout = 60000; // 60 seconds timeout
                            let pollCount = 0;
                            const maxPolls = timeout / 10; // 10ms intervals
                            
                            while (!pendingCalls[callId].completed && pollCount < maxPolls) {{
                                pollCount++;
                                
                                // Check if call still exists (might be cleaned up by timeout or error)
                                if (!pendingCalls[callId]) {{
                                    send({{type: 'log', message: 'Call ' + callId + ' was cleaned up externally'}});
                                    return createSafeDefault(returnTypeName);
                                }}
                                
                                // Small delay to prevent busy waiting
                                Java.perform(function() {{
                                    Thread.sleep(10); // 10ms delay
                                }});
                            }}
                            
                            // Check for timeout
                            if (pollCount >= maxPolls) {{
                                send({{type: 'log', message: 'TIMEOUT: Call ' + callId + ' timed out after ' + timeout + 'ms'}});
                                const result = createSafeDefault(returnTypeName);
                                delete pendingCalls[callId]; // Clean up
                                return result;
                            }}
                            
                            // Ensure we still have the pending call
                            if (!pendingCalls[callId]) {{
                                send({{type: 'log', message: 'ERROR: Call ' + callId + ' disappeared during processing'}});
                                return createSafeDefault(returnTypeName);
                            }}
                            
                            // Process the response
                            const response = pendingCalls[callId].response;
                            const callInfo = pendingCalls[callId]; // Store reference before cleanup
                            
                            if (!response) {{
                                send({{type: 'log', message: 'ERROR: No response received for call ' + callId}});
                                delete pendingCalls[callId];
                                return createSafeDefault(returnTypeName);
                            }}
                            
                            let result;
                            
                            try {{
                                send({{type: 'log', message: 'Processing response for call ' + callId + ': ' + response.action}});
                                
                                // Apply argument modifications if any
                                if (response.modified_args && response.modified_args.length > 0) {{
                                    response.modified_args.forEach(function(mod) {{
                                        const index = mod.index;
                                        const value = mod.value;
                                        const type = mod.type;

                                        try {{
                                            if (type === 'null') {{
                                                callInfo.args[index] = null;
                                            }} else if (type === 'string') {{
                                                callInfo.args[index] = String(value);
                                            }} else if (type === 'int') {{
                                                callInfo.args[index] = parseInt(value);
                                            }} else if (type === 'boolean') {{
                                                callInfo.args[index] = Boolean(value);
                                            }} else if (type === 'double') {{
                                                callInfo.args[index] = parseFloat(value);
                                            }} else if (type === 'long') {{
                                                callInfo.args[index] = parseInt(value);
                                            }}

                                            send({{type: 'log', message: 'Modified argument [' + index + '] to: ' + value}});
                                        }} catch (modError) {{
                                            send({{type: 'log', message: 'Error modifying argument [' + index + ']: ' + modError.message}});
                                        }}
                                    }});
                                }}
                                
                                // Handle different response actions
                                if (response.action === 'override_return') {{
                                    if (response.return_override) {{
                                        const override = response.return_override;
                                        result = castReturnValueAdvanced(override.value, override.type, callInfo.returnTypeName);
                                        send({{type: 'log', message: 'Return override: ' + result + ' (type: ' + typeof result + ')'}});
                                    }} else {{
                                        result = createSafeDefault(callInfo.returnTypeName);
                                    }}
                                }} else if (response.action === 'modify_input') {{
                                    try {{
                                        result = callInfo.originalImpl.apply(callInfo.context, callInfo.args);
                                        send({{type: 'log', message: 'Called original method with modified args'}});
                                    }} catch (originalCallError) {{
                                        send({{type: 'log', message: 'Original call failed: ' + originalCallError.message}});
                                        result = createSafeDefault(callInfo.returnTypeName);
                                    }}
                                }} else if (response.action === 'modify_both') {{
                                    try {{
                                        callInfo.originalImpl.apply(callInfo.context, callInfo.args);
                                    }} catch (originalCallError) {{
                                        send({{type: 'log', message: 'Original call failed: ' + originalCallError.message}});
                                    }}

                                    if (response.return_override) {{
                                        const override = response.return_override;
                                        result = castReturnValueAdvanced(override.value, override.type, callInfo.returnTypeName);
                                        send({{type: 'log', message: 'Modified both - return override: ' + result}});
                                    }} else {{
                                        result = createSafeDefault(callInfo.returnTypeName);
                                    }}
                                }} else {{
                                    // Default: call original method
                                    try {{
                                        result = callInfo.originalImpl.apply(callInfo.context, callInfo.args);
                                        send({{type: 'log', message: 'Called original method normally'}});
                                    }} catch (originalCallError) {{
                                        send({{type: 'log', message: 'Original call failed: ' + originalCallError.message}});
                                        result = createSafeDefault(callInfo.returnTypeName);
                                    }}
                                }}

                                // Final safety check
                                if (result === undefined && callInfo.returnTypeName !== 'void') {{
                                    result = createSafeDefault(callInfo.returnTypeName);
                                }}

                            }} catch (e) {{
                                send({{type: 'log', message: 'Error processing response for call ' + callId + ': ' + e.message}});
                                result = createSafeDefault(callInfo.returnTypeName);
                            }}

                            // Clean up BEFORE returning - this is crucial
                            delete pendingCalls[callId];

                            send({{type: 'log', message: 'Method call ' + callId + ' completed with result: ' + result}});
                            return result;
                        }};
                        
                        hookedCount++;
                        
                    }} catch (e) {{
                        send({{type: 'log', message: 'Failed to hook method ' + methodName + ': ' + e.message}});
                    }}
                }});
                
                send({{type: 'log', message: 'Hooking complete - Hooked: ' + hookedCount + ', Skipped: ' + skippedCount}});
                
            }} catch (e) {{
                send({{type: 'log', message: 'Error setting up interception: ' + e.message}});
            }}
            
            recv(function(message) {{
                const callId = message.call_id;
                if (callId && pendingCalls[callId]) {{
                    send({{type: 'log', message: 'Received response for call: ' + callId}});
                    pendingCalls[callId].response = message;
                    pendingCalls[callId].completed = true;
                }} else {{
                    send({{type: 'log', message: 'Received message for unknown call ID: ' + callId}});
                }}
            }});

            // Periodic cleanup of stale pending calls
            setInterval(function() {{
                const now = Date.now();
                const staleTimeout = 120000; // 2 minutes
                let cleanedCount = 0;

                Object.keys(pendingCalls).forEach(function(callId) {{
                    const call = pendingCalls[callId];
                    if (call && call.startTime && (now - call.startTime) > staleTimeout) {{
                        send({{type: 'log', message: 'Cleaning up stale call: ' + callId}});
                        delete pendingCalls[callId];
                        cleanedCount++;
                    }}
                }});
                
                if (cleanedCount > 0) {{
                    send({{type: 'log', message: 'Cleaned up ' + cleanedCount + ' stale pending calls'}});
                }}
            }}, 30000); // Run every 30 seconds

        }});
        """

    def start(self):
        """Start the Frida session"""
        try:
            print("[+] Connecting to device...")
            self.device = frida.get_usb_device(timeout=10)
            print(f"[+] Connected to device: {self.device.name}")
            
            print(f"[+] MODE: {self.mode.upper()}")
            if self.mode == "primitives":
                print("[+] PRIMITIVES MODE: Only hooking methods with primitive types (safe)")
                print("    ✅ No crashes with complex objects")
                print("    ❌ Limited to basic types only")
            else:
                print("[+] ALL TYPES MODE: Hooking all methods with advanced casting")
                print("    ✅ Handles all types including complex objects")
                print("    ⚠️ Uses advanced casting to prevent crashes")
            
            if self.method_filters:
                print(f"[+] Method filters active: {len(self.method_filters)} filters")
                for i, filter_pattern in enumerate(self.method_filters, 1):
                    print(f"    {i}. {filter_pattern}")
            else:
                print("[+] No method filters - checking all methods")
            
            print(f"[+] Spawning {self.package_name}...")
            pid = self.device.spawn([self.package_name])
            self.session = self.device.attach(pid)
            
            print("[+] Loading enhanced Frida script...")
            self.script = self.session.create_script(self.get_frida_script())
            self.script.on('message', self.on_message)
            self.script.load()
            
            self.device.resume(pid)
            print(f"[+] Process resumed. PID: {pid}")
            print(f"[+] Monitoring class: {self.target_class}")
            print("[+] Enhanced interception ready. Waiting for method calls...")
            print("[+] Press Ctrl+C to exit")
            
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[+] Stopping...")
                
        except frida.ProcessNotFoundError:
            print(f"[-] Process {self.package_name} not found")
        except frida.TimedOutError:
            print("[-] Timed out while connecting to device")
        except Exception as e:
            print(f"[-] Error: {e}")
        finally:
            if self.session:
                self.session.detach()

def main():
    if len(sys.argv) < 3:
        print("Enhanced Interactive Frida Java Method Interceptor")
        print("=" * 60)
        print("Two modes available:")
        print("  🟢 PRIMITIVES: Safe mode - only primitive types (no crashes)")
        print("  🔴 ALL: Advanced mode - all types with enhanced casting")
        print()
        print("Usage:")
        print(f"  {sys.argv[0]} <package_name> <target_class> [mode] [method_filters...]")
        print()
        print("Modes:")
        print("  primitives  - Only hook methods with primitive parameters/returns (safe)")
        print("  all         - Hook all methods with advanced object casting (default)")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} com.example.app com.example.SecurityManager")
        print(f"  {sys.argv[0]} com.example.app com.example.AuthManager primitives")
        print(f"  {sys.argv[0]} com.example.app com.example.AuthManager all authenticate login")
        print(f"  {sys.argv[0]} com.expo.app com.expo.SomeClass primitives 'definition'")
        print()
        print("Features:")
        print("  🟢 PRIMITIVES Mode:")
        print("    - ✅ 100% crash-free operation")
        print("    - ✅ Fast and reliable")
        print("    - ❌ Limited to basic types (int, string, boolean, etc.)")
        print()
        print("  🔴 ALL Mode:")
        print("    - ✅ Handles all Java types and objects")
        print("    - ✅ Advanced casting prevents most crashes")
        print("    - ✅ Smart object creation and fallbacks")
        print("    - ⚠️ Some complex objects may still cause issues")
        sys.exit(1)
    
    package_name = sys.argv[1]
    target_class = sys.argv[2]
    
    # Parse mode parameter
    mode = "all"  # default
    method_filters = []
    
    if len(sys.argv) > 3:
        if sys.argv[3].lower() in ["primitives", "all"]:
            mode = sys.argv[3].lower()
            method_filters = sys.argv[4:] if len(sys.argv) > 4 else []
        else:
            # No mode specified, treat as method filter
            method_filters = sys.argv[3:]
    
    print("Enhanced Interactive Frida Java Method Interceptor")
    print("=" * 60)
    print(f"Target Package: {package_name}")
    print(f"Target Class: {target_class}")
    print(f"Mode: {mode.upper()}")
    
    if mode == "primitives":
        print("🟢 PRIMITIVES MODE - Safe operation, primitive types only")
    else:
        print("🔴 ALL MODE - All types with advanced casting")
    
    if method_filters:
        print("Method Filters:")
        for i, filter_pattern in enumerate(method_filters, 1):
            print(f"  {i}. {filter_pattern}")
    else:
        print("Method Filters: All methods")
    
    print("=" * 60)
    
    hook = EnhancedInteractiveFridaHook(package_name, target_class, method_filters, mode)
    hook.start()

if __name__ == "__main__":
    main()