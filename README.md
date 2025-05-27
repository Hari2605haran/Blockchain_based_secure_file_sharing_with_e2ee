# 🔐 Blockchain-Based Secure File Sharing System with End-to-End Encryption

This project is a secure, decentralized file sharing platform that combines **Blockchain technology** and **End-to-End Encryption (E2EE)** to ensure data confidentiality, integrity, and access control. Built using Python, Flask, and cryptographic libraries, the system removes reliance on centralized servers and introduces immutable blockchain logging for all transactions.

## 📌 Features

- 🔒 **AES-256 Encryption**: Files are encrypted locally before transmission.
- 🔑 **RSA Key Exchange**: Only the intended recipient can decrypt the file using their private key.
- ⛓️ **Blockchain Logging**: Each file transaction is securely recorded with SHA-256 hashing.
- ✅ **End-to-End Confidentiality**: No third party, including the server, can access the file contents.
- 📜 **Tamper Detection**: SHA-256 hash ensures file integrity.
- 📊 **User Dashboard**: Web interface for uploading/downloading and viewing transaction logs.

## 🧠 How It Works

1. **User Authentication**: Users register/login securely.
2. **File Encryption**: The sender encrypts the file using AES-256.
3. **Key Exchange**: Encryption keys are securely exchanged using RSA.
4. **Blockchain Logging**: Metadata (sender, receiver, timestamp) and file hash are stored immutably.
5. **Secure File Sharing**: Encrypted file is sent via a secure channel.
6. **Decryption**: Recipient decrypts the file using their RSA private key.

## 🛠️ Tech Stack

| Component        | Technology           |
|------------------|----------------------|
| Backend          | Python 3.11, Flask   |
| Encryption       | AES-256 (Fernet), RSA|
| Hashing          | SHA-256 (hashlib)    |
| Database         | SQLite3              |
| Blockchain Ledger| Custom Python-based  |
| Frontend         | HTML, CSS            |
| API Testing      | Postman              |

## 🚀 Performance Overview

| Metric                  | Legacy Cloud | Proposed System | Improvement          |
|--------------------------|--------------|------------------|-----------------------|
| Encryption Speed         | Moderate     | Fast (AES-based) | Faster & Secure       |
| Decryption Reliability   | Varies       | 100%             | Key-bound Access      |
| Data Integrity Check     | Manual       | Auto (SHA-256)   | Tamper Detection      |
| Storage Privacy          | Plain files  | Encrypted        | Full Confidentiality  |
| Auditability             | None         | Full Log         | Transparent History   |

## 🔮 Future Enhancements

- 🤖 **Smart Contract Integration** for automated access control.
- 📦 **Decentralized File Storage (IPFS)** for off-chain file storage.
- 📲 **Mobile App Support** for on-the-go access.
- 🔐 **Multi-Factor Authentication** for added login security.
- 🧠 **Zero-Knowledge Proofs** to verify access without revealing file contents.

## 💻 Installation

```bash
git clone https://github.com/Hari2605haran/secure-file-share-blockchain.git
cd secure-file-share-blockchain
pip install -r requirements.txt
python app.py
