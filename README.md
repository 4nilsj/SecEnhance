# SecEnhance: Security Automation Toolkit

A suite of advanced security automation tools for application, API, and mobile security testing. Includes:
- **Mobile Security Testing Tool** (Drozer/MobSF-like)
- **JWT Security Testing Tool**
- **OAuth/OIDC Security Testing Tool**
- **Automated Security Scanner**
- **Security Checklist Generator**

## 🐍 Requirements

- **Python 3.8 or higher** (Python 2 is not supported)
- All tools require Python 3.8+ for optimal performance and security features

## 📦 Tools Overview

| Tool         | Description                                      | Location         |
|--------------|--------------------------------------------------|------------------|
| Mobile Tool  | Automated static, dynamic, network, and storage analysis for Android apps | [mobile_tool/](mobile_tool/) |
| JWT Tool     | JWT token security testing and vulnerability checks | [jwt_tool/](jwt_tool/) |
| OAuth Tool   | OAuth/OIDC flow and token security testing         | [oauth_tool/](oauth_tool/) |
| Scanner Tool | Automated security scanner for code and config     | [scanner_tool/](scanner_tool/) |
| Checklist    | Security checklist generator with test procedures  | [checklist_tool/](checklist_tool/) |

## 🚀 Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/4nilsj/SecEnhance.git
   cd SecEnhance
   ```

2. **Verify Python version**
   ```bash
   python --version
   # Should show Python 3.8 or higher
   ```

3. **Choose a tool and install its dependencies**
   ```bash
   cd mobile_tool
   pip install -r requirements.txt
   # or for jwt_tool, oauth_tool, etc.
   ```

4. **Run the tool**
   ```bash
   python src/mobile_security_tester.py --help
   # or see the tool's README for usage
   ```

## 📚 Documentation

- [Mobile Tool Documentation](mobile_tool/README.md)
- [JWT Tool Documentation](jwt_tool/README.md)
- [OAuth Tool Documentation](oauth_tool/README.md)
- [Scanner Tool Documentation](scanner_tool/README.md)
- [Checklist Tool Documentation](checklist_tool/README.md)
- [General Docs](docs/)

## 🛠️ Editor setup (Pylance/Pyright)

If your editor reports unresolved imports for shared modules (e.g., `utils` inside tool folders), this repository includes a `pyrightconfig.json` that adds the necessary source paths for analysis. Most users won't need to change anything.

- Pyright/Pylance: `pyrightconfig.json` contains `extraPaths` such as `burp_automation_tool/src`.
- VS Code: `.vscode/settings.json` sets `python.analysis.extraPaths` accordingly.
- Alternative: set `PYTHONPATH` to include the tool's `src` directory when running scripts manually.

## 🗂️ Repository Structure

```
SecEnhance/
├── mobile_tool/
├── jwt_tool/
├── oauth_tool/
├── scanner_tool/
├── checklist_tool/
├── docs/
├── examples/
├── .gitignore
├── README.md
└── LICENSE
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

These tools are for educational and authorized security testing purposes only. Always ensure you have proper authorization before testing any application. The authors are not responsible for any misuse of this toolkit. 