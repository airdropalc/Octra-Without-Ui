# 🚀 Octra Wallet CLI (No-UI Performance Version)

This project provides a lightweight, command-line (CLI) version of the Octra Wallet. It was created as a high-performance alternative to the official UI-based wallet, specifically designed to be stable and fast on devices that experienced crashes or slowdowns with the original version.

By removing the graphical user interface, this script offers a more robust and resource-friendly way to interact with the Octra network.

[![Telegram](https://img.shields.io/badge/Community-Airdrop_ALC-26A5E4?style=for-the-badge&logo=telegram)](https://t.me/airdropalc/2779)

---

## ✅ Getting Started: Prerequisites

Before you run the installation script, you **must** complete the following two steps.

### Step 1: Generate an Octra Wallet
You need to create a wallet first to get your private key and address. Use the official wallet generation tool for this.
* **Go to:** [**octra-labs/wallet-gen**](https://github.com/octra-labs/wallet-gen) and follow their instructions.

### Step 2: Request Faucet Funds
Your newly created wallet needs testnet funds to operate. Request tokens from the official faucet.
* **Go to:** [**Official Octra Faucet**](https://faucet.octra.network/)

---

## 🛠️ Installation & Configuration

### Step 3: One-Click Installation
Once you have your wallet credentials and faucet funds, run the single command below in your terminal. This will clone the repository, navigate into the directory, and execute the installation script.

```bash
git clone https://github.com/airdropalc/Octra-Without-Ui.git && cd Octra-Without-Ui && chmod +x install_octra.sh && ./install_octra.sh
```

### Step 4: Configure `wallet.json`
After running the installer, you will need to configure your `wallet.json` file with the credentials you generated in Step 1.

Create a file named `wallet.json` in the project directory and paste the following content, replacing the placeholder text with your actual information.

**`wallet.json` Example:**
```json
{
  "priv": "YOUR-PRIVATE-KEY-HERE",
  "addr": "YOUR-octx-WALLET-ADDRESS-HERE",
  "rpc": "[https://octra.network](https://octra.network)"
}
```
* `priv`: Your wallet's private key.
* `addr`: Your public wallet address (starts with `octx`).
* `rpc`: The RPC endpoint for the network (should be left as is).

---

## 💻 Using the Wallet

This is a **headless (no-UI)** wallet. All interactions happen through your command-line terminal. Follow any on-screen instructions provided by the script after installation to use the wallet's functions.

## 🔗 Important Links

* **Official Website:** [octra.org](https://octra.org/)
* **Original UI Wallet:** [octra-labs/octra_pre_client](https://github.com/octra-labs/octra_pre_client)
* **Wallet Generator:** [octra-labs/wallet-gen](https://github.com/octra-labs/wallet-gen)
* **Official Faucet:** [faucet.octra.network](https://faucet.octra.network/)

---

## ⚠️ Security Disclaimer

**Handle your `wallet.json` file and private key with extreme care.**

* Your private key grants **complete and irreversible control** over your wallet and funds.
* **NEVER** share your private key or commit your `wallet.json` file to a public repository.
* This software is provided for educational and experimental purposes. The authors are not responsible for any loss of funds. **Your security is your responsibility.**

---
> Inspired by and developed for the [Airdrop ALC](https://t.me/airdropalc) community.

## License

![Version](https://img.shields.io/badge/version-1.1.0-blue)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)]()

---
