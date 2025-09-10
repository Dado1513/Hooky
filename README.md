# Hooky 


<div align="center">
<img src="assets/hooky_icon.png" alt="Description" width="200" height="200">
</div>

**Hooky** is a dynamic analysis tool for mobile application security testing and runtime instrumentation.



## ⭐ Features
- 🔍 **Function Hooking** - Intercept and analyze native (Java & Kotlin) method calls
- 📱 **Multi-Platform** - Android support (iOS coming soon)  
- 🛡️ **Security Testing** - Bypass protections and uncover hidden behaviors
- ⚡ **Easy to Use** - Simple CLI interface for rapid analysis

Perfect for security researchers, penetration testers, and mobile app analysts who need to perform deep runtime inspection and vulnerability assessment.


## 📋 Complete File Structure

Hooky:

```
Hooky/
├── hooky_easy.py        # Quick utilities and CLI ANDROID ONLY 
... Coming Soon
└── README.md                    # This usage guide
```

## 🎯 Quick Start

### Requirements
- Python 3.12+
- frida-server 16.7.19 (must be running on target device)
- uv (Python package manager)

### Installation
```bash
uv venv
# Activate virtual environment
# On Unix/macOS:
source .venv/bin/activate

# On Windows:
.venv\Scripts\activate

# Sync dependencies to active/project virtual environment
uv sync
```
### Setup frida-server
```bash
# Download and setup frida-server 16.7.19 on your target device
# For Android:
adb push frida-server-16.7.19-android-arm64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

```

### Basic Usage

```bash
# Quick Utilities - Fast testing
uv run hooky_easy.py com.example.app com.example.AuthManager
uv run hooky_easy.py com.example.app 'login.*' 'auth.'
uv run hooky_easy.py --cli
```

## 📚 Resources

- **Frida Documentation**: https://frida.re/docs/
- **Android Reverse Engineering**: https://github.com/android/security-samples
- **iOS Security**: https://github.com/OWASP/owasp-mastg
- **Method Signature Reference**: https://docs.oracle.com/javase/tutorial/reflect/
- **Regex Testing**: https://regex101.com/ (for testing method filter patterns)


## 🤝 Contributing

Feel free to extend these scripts with additional features:
- Custom data type support
- GUI interface
- Database logging
- Network interception
- Advanced pattern matching
- Method signature analysis
- Cross-platform support (iOS)     