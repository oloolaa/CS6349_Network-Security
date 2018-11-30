# Implementation of a Real-Time e-Commerce Broker System

This project is an implementation an e-Commerce broker system which will facilitate anonymous online purchase process between a Client and an e-Commerce Website. By Yinglue Chen, Rohith Kilambi, Sampath Grandhi for Network Security CS6349.001 Fall 18 by Prof. Kamil Sarac.



## Features

- Integrity verification
- Authentication
- Anonymity
- Non-repudiation



## Installation

We've used Java 8+.
The client runs at xxx port.
The broker runs at 5000 port.
The Server1 runs at 6000 port.
The Server2 runs at 1234 port.

In our project, we've used “javax.crypto” and “java.security” packages for the keys and “java.net” packages for the socket.


## Usage

```
GenerateKeys.java
```
This is used for generating the public-private key pair. The lengths of the keys for client, broker, and seller are different, which are 3072 bits, 1024 bits, and 2048 bits. This file should be executed first to generate keys.

```
InputPort.java
```
This file is for the broker. When executing this file, a CSV file containing the information about the sellers and ports will be automatically generated, which will be used later for the communication between broker and seller.

```
InputUserPwd.java
```
This file is for the broker. When executing this file, a CSV file containing the information about the usernames and the hash values of the users’ passwords will be automatically generated, which will be used later for the verification when client logins to the broker.

```
Broker.java
```
When executing this file, the broker system will start. During the process, the broker will keep listening until one client tries to log in. Once the client inputs a valid seller name, the broker will connect to the corresponding seller, and then the purchase can be performed.


## Screenshots

* The CSV file storing the sellers’ names and their corresponding ports:


* The CSV file storing the usernames and the hash value of their corresponding passwords:


* The result from the broker after one execution:



## References
