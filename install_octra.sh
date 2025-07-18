#!/bin/bash

function show_banner() {
    clear
    echo "===================================================="
    echo "         OCTRA AUTO-INSTALLER BY AIRDROPALC         "
    echo "===================================================="
    echo "               https://t.me/airdropalc              "
    echo "          Date: $(date '+%B %d, %Y, %r %Z')"
    echo "----------------------------------------------------"
}

function configure_wallet() {
    if [ -f "wallet.json" ]; then
        echo "✅ Existing wallet.json found."
        read -p "Use the existing wallet or create a new one? (use/new): " wallet_choice
        if [[ "$wallet_choice" != "new" ]]; then
            echo "Using existing wallet.json."
            return 0
        fi
    fi

    echo "⚙️ Please provide your wallet details to create/update wallet.json."
    
    read -sp "Enter your private key: " user_priv_key
    echo
    read -p "Enter your address (octx...): " user_addr

    if [ -z "$user_priv_key" ] || [ -z "$user_addr" ]; then
        echo "❌ Private key and address cannot be empty. Wallet creation failed."
        return 1
    fi

    printf '{\n  "priv": "%s",\n  "addr": "%s",\n  "rpc": "https://octra.network"\n}\n' "$user_priv_key" "$user_addr" > wallet.json

    echo "✅ wallet.json created/updated successfully."
    return 0
}

function check_dependencies() {
    echo "🔎 Checking system dependencies (git, python3, pip3)..."
    local missing_pkg=0

    command -v git >/dev/null 2>&1 || { echo "❌ Git not found."; missing_pkg=1; }
    command -v python3 >/dev/null 2>&1 || { echo "❌ Python 3 not found."; missing_pkg=1; }
    command -v pip3 >/dev/null 2>&1 || { echo "❌ pip3 not found."; missing_pkg=1; }

    if [ $missing_pkg -eq 1 ]; then
        echo "----------------------------------------------------"
        echo "⚠️  Some required packages are not installed."
        echo "Please install them using the appropriate command for your system:"
        echo "sudo apt update && sudo apt install git python3 python3-pip -y  (For Debian/Ubuntu)"
        echo "sudo dnf install git python3 python3-pip -y                  (For Fedora/CentOS)"
        echo "----------------------------------------------------"
        read -p "Press [Enter] to return to the main menu..."
        return 1
    fi
    echo "✅ Core dependencies are satisfied."
    return 0
}

function full_install() {
    show_banner
    echo "⚙️  Starting Full Installation Process..."
    echo "----------------------------------------------------"
    check_dependencies || return 1
    echo "📂 Cloning repository from GitHub..."
    if [ -d "Octra-Without-Ui" ]; then
        echo "Directory 'Octra-Without-Ui' already exists. Skipping clone."
    else
        git clone https://github.com/airdropalc/Octra-Without-Ui.git
    fi
    cd Octra-Without-Ui || { echo "Failed to enter directory Octra-Without-Ui."; return 1; }
    echo "✅ Repository is ready."
    echo "🐍 Setting up Python virtual environment (venv)..."
    if ! python3 -m venv venv > /dev/null 2>&1; then
        echo "⚠️  Failed to create venv. The 'python3-venv' package is likely missing."
        read -p "Attempt to install 'python3-venv' now? (y/n): " confirm
        if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
            if command -v apt >/dev/null 2>&1; then
                sudo apt update && sudo apt install python3-venv -y
            elif command -v dnf >/dev/null 2>&1; then
                sudo dnf install python3-venv -y
            else
                echo "Could not detect package manager (apt/dnf). Installation failed."
                cd ..
                return 1
            fi
            python3 -m venv venv
        else
            echo "Installation cancelled."
            cd ..
            return 1
        fi
    fi
    echo "✅ Venv created successfully."
    echo "📦 Installing all requirements..."
    source venv/bin/activate
    pip install -r requirements.txt
    deactivate
    echo "----------------------------------------------------"
    echo "🎉 INSTALLATION COMPLETE! 🎉"
    echo "All files and dependencies have been set up successfully."
    cd ..
    read -p "Press [Enter] to return to the main menu..."
}

function run_octra() {
    show_banner
    echo "🚀 Running Octra..."
    echo "----------------------------------------------------"
    if [ ! -d "Octra-Without-Ui/venv" ]; then
        echo "❌ Installation directory or venv not found."
        echo "Please run the 'Full Installation' (Option 1) first."
        read -p "Press [Enter] to return to the main menu..."
        return
    fi
    
    cd Octra-Without-Ui
    configure_wallet || {
        echo "Aborting run due to wallet configuration issue."
        cd ..
        read -p "Press [Enter] to return to the main menu..."
        return
    }
    
    echo "Activating venv and running the python script..."
    echo "To stop the script, press CTRL+C."
    echo "----------------------------------------------------"
    source venv/bin/activate
    python3 octra.py
    
    echo "----------------------------------------------------"
    echo "The Octra script has stopped."
    deactivate
    cd ..
    read -p "Press [Enter] to return to the main menu..."
}

function update_dependencies() {
    show_banner
    echo "🔄 Updating / Re-installing Dependencies..."
    echo "----------------------------------------------------"
    if [ ! -d "Octra-Without-Ui/venv" ]; then
        echo "❌ Installation directory or venv not found."
        echo "Please run the 'Full Installation' (Option 1) first."
        read -p "Press [Enter] to return to the main menu..."
        return
    fi
    cd Octra-Without-Ui
    echo "Activating venv and updating dependencies from requirements.txt..."
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    deactivate
    echo "----------------------------------------------------"
    echo "✅ Dependencies updated successfully."
    cd ..
    read -p "Press [Enter] to return to the main menu..."
}

while true; do
    show_banner
    echo "MAIN MENU - What would you like to do?"
    echo "  1. Full Installation (Recommended for first time)"
    echo "  2. Run Octra (If already installed)"
    echo "  3. Update / Re-install Dependencies"
    echo "  4. Exit"
    echo ""
    read -p "Select an option [1-4]: " choice

    case $choice in
        1)
            full_install
            ;;
        2)
            run_octra
            ;;
        3)
            update_dependencies
            ;;
        4)
            echo "Thank you for using this script. Goodbye!"
            exit 0
            ;;
        *)
            echo "⚠️  Invalid option. Please try again."
            sleep 2
            ;;
    esac
done