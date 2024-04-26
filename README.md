# Secure Banking System Project

## Introduction

The Secure Banking System project is designed to implement advanced security protocols for a simulated banking environment. The aim is to develop a secure framework that authenticates users and ensures the integrity and confidentiality of transaction data between ATMs and the bank server. This project utilizes authenticated key distribution protocols and security protocols for data transactions to protect user interactions such as deposits, withdrawals, and balance inquiries.

## Project Components

- **Authentication and Key Management**: Designing a protocol where the ATM and bank server authenticate each other and establish a session-specific symmetric key.
- **Key Derivation**: Developing methods to derive encryption and MAC keys from the Master Secret to secure transaction data.
- **Secure Transaction Protocols**: Designing methods to encrypt transaction data and generate verifiable MACs to ensure data confidentiality and integrity.
- **Audit Logging**: Implementing an audit log to record all customer transactions in an encrypted format.
- **User Interface**: Creating intuitive GUI interfaces for the ATMs and the bank server to facilitate client interaction.

## Technical Architecture

The system is built with a client-server architecture, focusing on secure communications and cryptographic operations. On the server side, an RSA key pair is generated at startup, which is used for encrypting transaction logs and other secure operations. The server listens on port 5555 for incoming connections, handling each in a separate thread. The client side features a GUI developed using Tkinter, allowing for straightforward user interactions like registration and login.

## Conclusion

This project has provided valuable insights into the implementation of security measures in digital banking environments. It emphasizes the importance of robust authentication mechanisms and the combination of symmetric and asymmetric encryption techniques to safeguard data integrity and confidentiality. These elements are critical for protecting against unauthorized access and ensuring the safety of sensitive data across various platforms.

## How to Use

1. **Set up the environment**: Ensure Python and all required libraries are installed.
2. **Start the server**: Run `server.py` to initiate the server.
3. **Run the client application**: Launch `client.py` to start the ATM interface.
4. **Perform transactions**: Use the GUI to perform banking transactions securely.
