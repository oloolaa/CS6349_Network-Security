# Implementation of a Real-Time e-Commerce Broker System


## Overview

This project is an implementation an e-Commerce broker system which will facilitate anonymous online purchase process between a Client and an e-Commerce Website. By Yinglue Chen, Rohith Kilambi, Sampath Grandhi for Network Security CS6349.001 Fall 18 by Prof. Kamil Sarac.


## Features

- Authentication
- Message integrity verification
- Privacy/Confidentiality
- Anonymity
- Non-repudiation


## Language used

Java 8+.
- The broker runs at 5000 port.
- The Server1 runs at 6000 port.
- The Server2 runs at 1234 port.


## Package used
- javax.crypto and java.security for the cryptographic techniques(encryption and decryption).
- java.net for the socket.


## Files

```
GenerateKeys.java
```
This is used for generating the public-private key pair. The lengths of the keys for client, broker, and seller are 3072 bits, 1024 bits, and 2048 bits respectively. This file should be executed first to generate keys for each of the components.

```
InputPort.java
```
This file is for the broker. When executing this file, a CSV file containing the information about the sellers and ports will be automatically generated, which will be used later for the communication between broker and seller.

```
InputUserPwd.java
```
This file is for the broker. When executing this file, a CSV file containing the information about the usernames and the hash values of the users’ passwords will be automatically generated, which will be used later for the verification when the client logs in to the broker.

```
Broker.java
```
Executing this file, the broker system will start. During the process, the broker will keep listening until one client tries to log in. Once the client inputs a valid seller name, the broker will connect to the corresponding seller, and then the purchase can be performed.

```
Client.java
```
Executing this file, the client system will start. During the process, the client connects to the broker by logging into the broker system. Once logged in, the client must input a valid seller name. Once entered, the broker will connect to the corresponding seller. Then the client and seller can communicate with each other, where the broker cannot decrypt messages sent between client and seller and the seller doesn't know who the client is. The client shall send a request to the broker asking the seller to send the product catalog After receiving the product list, the client can select the product ID, the product is sent to the client via the broker and is downloaded into the client’s system.

```
Server.java
```
Executing this file, the server system will start. During the process, the server will keep listening for requests from the broker. The server verifies the broker and sends the product list to be served to the client. Upon receiving a request containing the product ID (after the broker completes the transaction) the seller delivers the product to the client. Server2.java is also implemented in the same manner.


## Instruction

1. First, run the following files. Change the path for the output files.
- GenerateKeys.java (change the key length and the file names to suit the client, broker, and seller)
- InputPort.java
- InputUserPwd.java
2. Run Server.java, Server2.java. Change the path for public key and private key files.
3. Run Broker.java. Change the path for public key and private key files.
4. Run Client.java. Change the path for public key and private key files.


## Working Scenario

1. Client enters username as “Alice”, Password as “1234”
2. Client inputs the server as Amazon and hits Enter which then sends a request for the product catalog.
3. Upon receiving a product catalog, the client selects a product ID and sends it to the broker for the transaction.
4. After successful completion of the transaction, the product is delivered by the server and received by the client.
