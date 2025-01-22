Secure Messaging System

Overview

The Secure Messaging System is a Java-based application designed to provide secure user authentication and encrypted messaging between users. It incorporates robust security features such as password hashing with salts, rate limiting to prevent brute force attacks, and AES encryption for message confidentiality.

Features

User Registration: Register new users with securely hashed passwords and unique salts.

User Authentication: Validate users with stored credentials and prevent unauthorized access.

Encrypted Messaging: Send and receive messages securely using AES encryption.

Rate Limiting: Protect accounts from brute force attacks with a lockout mechanism.

Database Integration: Use SQLite for storing user credentials and messages.

Prerequisites

Java Development Kit (JDK) 8 or later

SQLite JDBC driver

Installation

Clone the repository or download the source code.

Ensure you have SQLite installed and the SQLite JDBC driver available.

Compile the program using a Java compiler:

javac SecureMessagingSystem.java

Usage

Register a User

Run the program.

Call the registerUser method with a unique username and password:

SecureMessagingSystem.registerUser("username", "password");

Authenticate a User

Call the authenticateUser method with the username and password:

SecureMessagingSystem.authenticateUser("username", "password");

Send a Message

Use the sendMessage method to send an encrypted message to another user:

SecureMessagingSystem.sendMessage("sender", "receiver", "Your secure message here");

Read Messages

Use the readMessages method to view messages sent to a user:

SecureMessagingSystem.readMessages("username");

Security Details

Password Hashing: Uses SHA-256 with a unique salt for each user.

Message Encryption: Messages are encrypted with AES (128-bit key).

Rate Limiting: Accounts are locked for 1 minute after 5 consecutive failed login attempts.

Example Workflow

Register a user:

SecureMessagingSystem.registerUser("Alice", "password123");

Authenticate the user:

SecureMessagingSystem.authenticateUser("Alice", "password123");

Send a message:

SecureMessagingSystem.sendMessage("Alice", "Bob", "Hello, Bob!");

Read messages for Bob:

SecureMessagingSystem.readMessages("Bob");

Limitations

Encryption keys are generated dynamically and not persistently stored. This means encrypted messages can only be decrypted within the same runtime session.

The application does not currently support multi-threaded environments.

Future Enhancements

Persistent storage for encryption keys to support cross-session decryption.

A graphical user interface (GUI) for easier interaction.

Enhanced password policies for stronger security.
