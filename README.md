# Security-Programming

This project implements a WebSocket server using Python.  

## Requirements

- Python 3.12+
- Python packages:
  - `websockets`
  - `cryptography`

You can install dependencies using:

```
pip install websockets cryptography

```

## Running the Server
The server requires a unique ID and optionally host and port.
Basic command:

```
python server.py --id 1
```
## Running the Client
```
python client.py --user Alice --server ws://127.0.0.1:8765

```
```
python client.py --user Bob --server ws://127.0.0.1:8765

```





## commit 
```
# Stage all changes 
git add .

# Commit them
git commit -m "Update  client, server, keys and update README"

# Push to GitHub
git push origin main
```