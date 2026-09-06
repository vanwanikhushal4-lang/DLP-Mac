#!/usr/bin/env bash
#
# Velox Mac DLP - Terminal One-Liner Installer
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/vanwanikhushal4-lang/DLP-Mac/main/install.sh | bash
#
set -eo pipefail

VERSION="1.5.0"
REPO="vanwanikhushal4-lang/DLP-Mac"
RELEASE_URL="https://github.com/${REPO}/releases/download/v${VERSION}/VeloxMacDLP.zip"
TARGET_DIR="/Applications"
APP_PATH="${TARGET_DIR}/VeloxMacDLP.app"
TMP_DIR=$(mktemp -d)

# Styling
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${CYAN}${BOLD}"
cat << "EOF"
 __      __   _            __  __            _____  _      _____  
 \ \    / /  | |          |  \/  |          |  __ \| |    |  __ \ 
  \ \  / /___| | _____  __| \  / | __ _  ___| |  | | |    | |__) |
   \ \/ // _ \ |/ _ \ \/ /| |\/| |/ _` |/ __| |  | | |    |  ___/ 
    \  /|  __/ | (_) >  < | |  | | (_| | (__| |__| | |____| |     
     \/  \___|_|\___/_/\_\|_|  |_|\__,_|\___|_____/|______|_|     
EOF
echo -e "${NC}"
echo -e "${BOLD}Velox Mac DLP Installer (v${VERSION})${NC}"
echo "=================================================="

# 1. Platform Check
if [[ "$(uname)" != "Darwin" ]]; then
    echo -e "${RED}Error: Velox Mac DLP requires macOS.${NC}"
    exit 1
fi

OS_VERSION=$(sw_vers -productVersion | cut -d. -f1)
if [[ "${OS_VERSION}" -lt 14 ]]; then
    echo -e "${YELLOW}Warning: Velox Mac DLP is optimized for macOS 14 (Sonoma) or newer.${NC}"
fi

# 2. Terminate running instance if present
if pgrep -x "VeloxMacDLP" > /dev/null; then
    echo -e "${YELLOW}Stopping currently running VeloxMacDLP...${NC}"
    killall VeloxMacDLP 2>/dev/null || true
    sleep 1
fi

# 3. Download Release Archive
echo -e "\n${CYAN}==> Downloading Velox Mac DLP v${VERSION}...${NC}"
curl -fL --progress-bar "${RELEASE_URL}" -o "${TMP_DIR}/VeloxMacDLP.zip"

# 4. Extract to /Applications
echo -e "${CYAN}==> Installing to ${APP_PATH}...${NC}"
rm -rf "${APP_PATH}"
ditto -x -k "${TMP_DIR}/VeloxMacDLP.zip" "${TARGET_DIR}/"
rm -rf "${TMP_DIR}"

# 5. Remove quarantine attributes
echo -e "${CYAN}==> Stripping quarantine flags...${NC}"
xattr -cr "${APP_PATH}" || true

# 6. Register with LaunchServices
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "${APP_PATH}" 2>/dev/null || true

# 7. Launch Application
echo -e "${CYAN}==> Launching Velox Mac DLP...${NC}"
open "${APP_PATH}"

echo -e "\n${GREEN}${BOLD}✓ Velox Mac DLP successfully installed!${NC}"
echo "--------------------------------------------------"
echo -e "${YELLOW}${BOLD}Final Step: Approve System Extension${NC}"
echo "1. Go to: System Settings > Privacy & Security"
echo "2. Click 'Allow' under the security message for VeloxMacDLP"
echo "3. In 'Endpoint Security Extensions', ensure 'co.velox.macdlp.endpointsecurity' is ON."
echo "--------------------------------------------------"

# Offer to open Privacy & Security settings
if [[ -t 0 ]]; then
    read -p "Would you like to open Privacy & Security settings now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        open "x-apple.systempreferences:com.apple.preference.security?Privacy_Security"
    fi
fi
