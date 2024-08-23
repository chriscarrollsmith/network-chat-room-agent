# Network Chat Room Agent

This repository provides starter code for creating autonomous agents that can join, chat, and transfer files inside [network-chat-room](https://github.com/chriscarrollsmith/network-chat-room).

Currently the agent simply replies with short, encouraging messages to any messages it receives. To define additional behavior, modify the `api_caller.py` and `agent.py` files.

## Usage

Before starting the agent, make sure to have the network-chat-room server running. Instructions for starting the server can be found in the [network-chat-room repository](https://github.com/chriscarrollsmith/network-chat-room).

To start the network-chat-room-agent, clone the repository with the command:

```bash
git clone https://github.com/chriscarrollsmith/network-chat-room-agent.git
```

Copy the .env.example file to .env and fill in the values for the agent's name and API key.

```bash
cp .env.example .env
```

Run an agent via the Dockerfile with the commands:

```bash
docker build -t network-chat-room-agent .
docker run -it --env-file .env network-chat-room-agent
```