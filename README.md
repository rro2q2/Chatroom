# Cmp_Sc 4850 Lab 3: Version 2

## Overwiew
This project entails a chatroom in which as multiple client and a server that uses a socket API. The client then will connect to the server, allowing them to **login** using their username and password, **new user** with a new username and password, sending messages to all other clients using **send all**, or send to one client with the **send userID** command. The user see who else is logged by entering the **who command**. Once the user wants to log out, they can simply type in **logout**.

## Files
- chatroom.py: Implementation and main application of the chatroom.
- config.json: File containing configuration values in which server can use
- error_config.json: File lacking key configuration values in which application will detect

## Starting Up Chatroom Server
python3 chatroom.py --server --config <PATH_TO_CONFIG>

## Starting Up Chatroom Client
python3 chatroom.py
