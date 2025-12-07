#!/bin/bash

# Elite OSINT Bug Hunting Toolkit - Installation Script
# Automated setup for all dependencies and tools

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${PURPLE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                🔥 ELITE OSINT TOOLKIT INSTALLER 🔥           ║"
echo "║              Automated Setup & Configuration                ║"
echo "║                    Red Team OSINT Tools                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_warning "This script should not be run as root for security reasons"
   print_info "Please run as a regular user. Sudo will be used when needed."
   exit 1
fi

# Detect OS
print_info "Detecting operating system..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    print_status "Linux detected"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    print_status "macOS detected"
else
    print_error "Unsupported operating system: $OSTYPE"
    exit 1
fi

# Check Python version
print_info "Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
    print_status "Python 3 found: $(python3 --version)"
    
    # Check if version is 3.7 or higher
    if python3 -c "import sys; exit(0 if sys.version_info >= (3, 7) else 1)"; then
        print_status "Python version is compatible"
    else
        print_error "Python 3.7+ required. Current version: $PYTHON_VERSION"
        exit 1
    fi
else
    print_error "Python 3 not found. Please install Python 3.7+"
    exit 1
fi

# Check pip
print_info "Checking pip installation..."
if command -v pip3 &> /dev/null; then
    print_status "pip3 found"
else
    print_info "Installing pip3..."
    if [[ "$OS" == "linux" ]]; then
        sudo apt update && sudo apt install -y python3-pip
    elif [[ "$OS" == "macos" ]]; then
        curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
        python3 get-pip.py
        rm get-pip.py
    fi
    print_status "pip3 installed"
fi

# Install Python dependencies
print_info "Installing Python dependencies..."
pip3 install --user requests urllib3 pathlib argparse concurrent.futures threading json re time sys os subprocess datetime

# Check if installation was successful
if python3 -c "import requests, concurrent.futures, pathlib, argparse" 2>/dev/null; then
    print_status "Python dependencies installed successfully"
else
    print_error "Failed to install Python dependencies"
    exit 1
fi

# Install system tools
print_info "Installing system tools..."
if [[ "$OS" == "linux" ]]; then
    # Update package list
    print_info "Updating package list..."
    sudo apt update
    
    # Install essential tools
    print_info "Installing essential tools..."
    sudo apt install -y curl wget git jq nmap dnsutils whois
    
    # Install optional tools
    print_info "Installing optional tools..."
    sudo apt install -y masscan gobuster dirb nikto whatweb || print_warning "Some optional tools failed to install"
    
elif [[ "$OS" == "macos" ]]; then
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        print_info "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    # Install tools via Homebrew
    print_info "Installing tools via Homebrew..."
    brew install curl wget git jq nmap
    brew install masscan gobuster dirb nikto || print_warning "Some optional tools failed to install"
fi

print_status "System tools installed"

# Create directory structure
print_info "Creating directory structure..."
mkdir -p ~/elite_osint_toolkit
mkdir -p ~/elite_osint_toolkit/results
mkdir -p ~/elite_osint_toolkit/wordlists
mkdir -p ~/elite_osint_toolkit/logs

print_status "Directory structure created"

# Download additional wordlists
print_info "Downloading wordlists..."
cd ~/elite_osint_toolkit/wordlists

# Common subdomain wordlist
if [ ! -f "subdomains.txt" ]; then
    curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt" -o subdomains.txt || print_warning "Failed to download subdomain wordlist"
fi

# Admin panel wordlist
if [ ! -f "admin_panels.txt" ]; then
    curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" -o admin_panels.txt || print_warning "Failed to download admin panel wordlist"
fi

print_status "Wordlists downloaded"

# Set up aliases and shortcuts
print_info "Setting up aliases..."
ALIAS_FILE="$HOME/.bashrc"
if [[ "$OS" == "macos" ]]; then
    ALIAS_FILE="$HOME/.zshrc"
fi

# Add aliases if they don't exist
if ! grep -q "elite_osint" "$ALIAS_FILE" 2>/dev/null; then
    echo "" >> "$ALIAS_FILE"
    echo "# Elite OSINT Toolkit Aliases" >> "$ALIAS_FILE"
    echo "alias elite-osint='python3 ~/elite_osint_toolkit/elite_osint_master.py'" >> "$ALIAS_FILE"
    echo "alias elite-recon='python3 ~/elite_osint_toolkit/elite_recon_automation.py'" >> "$ALIAS_FILE"
    echo "alias elite-buckets='python3 ~/elite_osint_toolkit/cloud_bucket_hunter.py'" >> "$ALIAS_FILE"
    echo "alias elite-github='python3 ~/elite_osint_toolkit/github_secrets_hunter.py'" >> "$ALIAS_FILE"
    echo "alias elite-admin='python3 ~/elite_osint_toolkit/admin_panel_hunter.py'" >> "$ALIAS_FILE"
    print_status "Aliases added to $ALIAS_FILE"
else
    print_info "Aliases already exist"
fi

# Create configuration file
print_info "Creating configuration file..."
cat > ~/elite_osint_toolkit/config.json << EOF
{
    "version": "1.0",
    "installation_date": "$(date)",
    "python_version": "$(python3 --version)",
    "os": "$OS",
    "tools": {
        "nmap": "$(command -v nmap || echo 'not installed')",
        "curl": "$(command -v curl || echo 'not installed')",
        "wget": "$(command -v wget || echo 'not installed')",
        "git": "$(command -v git || echo 'not installed')",
        "jq": "$(command -v jq || echo 'not installed')"
    },
    "directories": {
        "toolkit": "~/elite_osint_toolkit",
        "results": "~/elite_osint_toolkit/results",
        "wordlists": "~/elite_osint_toolkit/wordlists",
        "logs": "~/elite_osint_toolkit/logs"
    }
}
EOF

print_status "Configuration file created"

# Create launcher script
print_info "Creating launcher script..."
cat > ~/elite_osint_toolkit/launch.sh << 'EOF'
#!/bin/bash

# Elite OSINT Toolkit Launcher
echo "🔥 Elite OSINT Toolkit Launcher"
echo "================================"
echo "1. Full OSINT Reconnaissance"
echo "2. Subdomain Enumeration"
echo "3. Cloud Bucket Hunting"
echo "4. GitHub Secrets Discovery"
echo "5. Admin Panel Hunting"
echo "6. Exit"
echo ""
read -p "Select option (1-6): " choice

case $choice in
    1)
        read -p "Enter target domain: " target
        read -p "Enter GitHub token (optional): " github_token
        if [ -n "$github_token" ]; then
            python3 elite_osint_master.py "$target" -g "$github_token"
        else
            python3 elite_osint_master.py "$target"
        fi
        ;;
    2)
        read -p "Enter target domain: " target
        python3 elite_recon_automation.py "$target"
        ;;
    3)
        read -p "Enter target domain: " target
        python3 cloud_bucket_hunter.py "$target"
        ;;
    4)
        read -p "Enter target domain: " target
        read -p "Enter GitHub token (optional): " github_token
        if [ -n "$github_token" ]; then
            python3 github_secrets_hunter.py "$target" "$github_token"
        else
            python3 github_secrets_hunter.py "$target"
        fi
        ;;
    5)
        read -p "Enter target domain: " target
        python3 admin_panel_hunter.py "$target"
        ;;
    6)
        echo "Goodbye!"
        exit 0
        ;;
    *)
        echo "Invalid option"
        ;;
esac
EOF

chmod +x ~/elite_osint_toolkit/launch.sh
print_status "Launcher script created"

# Create update script
print_info "Creating update script..."
cat > ~/elite_osint_toolkit/update.sh << 'EOF'
#!/bin/bash

echo "🔄 Updating Elite OSINT Toolkit..."

# Update Python packages
pip3 install --user --upgrade requests urllib3

# Update wordlists
cd ~/elite_osint_toolkit/wordlists
curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt" -o subdomains.txt
curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" -o admin_panels.txt

# Update system tools
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    sudo apt update && sudo apt upgrade -y nmap curl wget git jq
elif [[ "$OSTYPE" == "darwin"* ]]; then
    brew update && brew upgrade nmap curl wget git jq
fi

echo "✅ Update completed!"
EOF

chmod +x ~/elite_osint_toolkit/update.sh
print_status "Update script created"

# Final setup
print_info "Performing final setup..."

# Make all Python scripts executable
chmod +x ~/elite_osint_toolkit/*.py 2>/dev/null || true

# Create desktop shortcut (Linux only)
if [[ "$OS" == "linux" ]] && command -v desktop-file-install &> /dev/null; then
    cat > ~/Desktop/Elite-OSINT-Toolkit.desktop << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Elite OSINT Toolkit
Comment=Red Team OSINT Bug Hunting Tools
Exec=gnome-terminal -- bash -c "cd ~/elite_osint_toolkit && ./launch.sh; exec bash"
Icon=utilities-terminal
Terminal=false
Categories=Development;Security;
EOF
    chmod +x ~/Desktop/Elite-OSINT-Toolkit.desktop
    print_status "Desktop shortcut created"
fi

# Installation complete
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    🎉 INSTALLATION COMPLETE! 🎉             ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

print_status "Elite OSINT Toolkit installed successfully!"
echo ""
print_info "Installation Summary:"
echo "  📁 Toolkit Directory: ~/elite_osint_toolkit"
echo "  🐍 Python Version: $(python3 --version)"
echo "  🛠️  System Tools: nmap, curl, wget, git, jq"
echo "  📚 Wordlists: Downloaded to ~/elite_osint_toolkit/wordlists"
echo "  🚀 Launcher: ~/elite_osint_toolkit/launch.sh"
echo ""

print_info "Quick Start Commands:"
echo "  🔥 Full OSINT: elite-osint example.com"
echo "  🎯 Subdomain Enum: elite-recon example.com"
echo "  ☁️  Cloud Buckets: elite-buckets example.com"
echo "  🔍 GitHub Secrets: elite-github example.com"
echo "  🔐 Admin Panels: elite-admin example.com"
echo ""

print_info "Manual Launch:"
echo "  cd ~/elite_osint_toolkit"
echo "  ./launch.sh"
echo ""

print_warning "Important Notes:"
echo "  • Restart your terminal to use aliases"
echo "  • Get GitHub token for better results: https://github.com/settings/tokens"
echo "  • Only use on authorized targets"
echo "  • Follow responsible disclosure practices"
echo ""

print_info "For detailed usage instructions, see: ~/elite_osint_toolkit/USAGE_GUIDE.md"
echo ""
echo -e "${CYAN}Happy Hunting! 🎯🔥${NC}"