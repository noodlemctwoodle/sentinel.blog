# Sentinel.blog Repository

[![PowerShell](https://img.shields.io/badge/PowerShell-%235391FE.svg?style=flat&logo=powershell&logoColor=white)](https://learn.microsoft.com/en-us/powershell/)
[![Microsoft Azure](https://img.shields.io/badge/Microsoft%20Azure-0089D6?style=flat&logo=microsoft-azure&logoColor=white)](https://azure.microsoft.com/)
[![Azure DevOps](https://img.shields.io/badge/Azure%20DevOps-0078D7?style=flat&logo=azure-devops&logoColor=white)](https://azure.microsoft.com/en-us/products/devops)
[![KQL](https://img.shields.io/badge/KQL-Query%20Language-blue)](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)
[![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-0078D4?style=flat&logo=microsoft&logoColor=white)](https://azure.microsoft.com/en-us/products/microsoft-sentinel)
[![Azure Automation](https://img.shields.io/badge/Azure%20Automation-0089D6?style=flat&logo=microsoft-azure&logoColor=white)](https://azure.microsoft.com/en-us/products/automation)
[![Azure Lighthouse](https://img.shields.io/badge/Azure%20Lighthouse-0089D6?style=flat&logo=microsoft-azure&logoColor=white)](https://azure.microsoft.com/en-us/services/azure-lighthouse/)

Welcome to the official repository for [Sentinel.blog](https://sentinel.blog), a resource dedicated to Microsoft Sentinel automation, best practices, and security operations excellence.


### ☕ My Blog

<a href="https://sentinel.blog/#/portal/signup">
  <img src="https://sentinel.blog/content/images/size/w192h192/size/w256h256/2025/06/monty.png" alt="sentinel.blog" width="80"/>
  <br/>
  <strong>Subscribe to sentinel.blog</strong>
  <br/>
  Making Security SIEMlessly Simple
</a>

## 📖 About This Repository

This repository contains all the scripts, code samples, and solutions featured on Sentinel.blog. My goal is to provide security professionals with practical, ready-to-use tools that enhance Microsoft Sentinel deployments and streamline security operations.

## 🔐 Key Areas

- **Analytics Rule Management**: Scripts to update and manage Microsoft Sentinel analytics rules
- **Content Hub Solutions**: Automated deployment and updates for Content Hub solutions
- **Workbook Automation**: Tools to keep Sentinel workbooks current and optimised
- **Azure Automation**: Runbooks for scheduled maintenance and operations
- **Azure Lighthouse**: Cross-tenant management scripts for MSSPs and enterprises

## 🚀 Getting Started

Most scripts in this repository are designed to be used in the following ways:

1. **Azure Automation Runbooks**: The primary intended use, with system-assigned managed identities
2. **Local Execution**: For testing or on-demand operations
3. **Pipeline Integration**: For DevOps-oriented security teams

### Prerequisites

- PowerShell 7.x or higher
- Az PowerShell module
- Appropriate Azure permissions (varies by script)

### Installation

```powershell
# Clone this repository
git clone https://github.com/yourusername/sentinel-blog.git

# Navigate to the repository
cd sentinel-blog

# Review the README for specific scripts before running
```

## 📝 Documentation

Each script includes detailed documentation in the following format:

- **Synopsis**: Brief description of functionality
- **Description**: Detailed explanation of what the script does
- **Parameters**: All available parameters and their usage
- **Examples**: Practical examples showing how to use the script
- **Notes**: Additional information, dependencies, and considerations

## 🤝 Contributing

Contributions are welcome! If you'd like to contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure your code follows the existing style and includes proper documentation.

## 📋 Roadmap

- [ ] Enhanced KQL query library for custom detections
- [ ] Integration with Sentinel Repositories feature
- [ ] Microsoft Defender XDR automation scripts
- [ ] Multi-workspace management utilities
- [ ] Performance optimization tools

## 💪 Support This Project

If you find this project helpful, there are several ways you can support its development:

### ⭐ Give a Star

If you find this repository useful, please give it a star on GitHub. This helps others discover it.

### 🔄 Share Your Experience

Share how you've used these scripts on [Sentinel.blog](https://sentinel.blog) or on social media, and tag me.

### 🐛 Report Issues

Found a bug or have a feature request? Open an issue on GitHub or submit a pull request.

### 🔍 Provide Feedback

Your feedback helps improve these tools. Reach out with suggestions or ideas for improvement.

### 🤝 Contribute

Contribute your own scripts, improvements, or documentation enhancements through pull requests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

*The scripts and tools in this repository are provided as-is without warranty. Always test in a non-production environment before operational use.*
