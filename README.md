# Onkyo eISCP Web Controller

A lightweight, secure, and responsive web-based remote control for Onkyo A/V receivers over the network using the eISCP protocol. Built with Python, Flask, and Waitress, with a modern TailwindCSS frontend.

## Features

- **Modern Web Interface**: Clean, responsive UI with glassmorphism effects and animations.
- **Core Controls**: Power, Master Volume, Mute.
- **Tone & Audio Levels**: Bass, Treble, Subwoofer, and Center channel control.
- **Input Selection**: Easily switch between NET, TV/CD, BD/DVD, CBL/SAT, and GAME.
- **Listening Modes**: Switch between Stereo, Direct, Surround, and PLII Movie.
- **Bi-directional Sync**: Automatically queries and syncs the current state of the receiver on load.
- **Built-in Security**:
  - Rate limiting to prevent abuse.
  - Strict allowlists (Regex) for commands and queries to prevent injection.
  - Target IP validation (only allows connections to private network IPs).
  - Secure HTTP headers (CSP, X-Frame-Options, X-XSS-Protection).

## Prerequisites

- Python 3.7+
- A network-connected Onkyo Receiver (with eISCP protocol support)

## Installation

1. Clone this repository or download the `onkyo.pyw` file.
2. Install the required Python dependencies:

```bash
pip install flask waitress
```

## Usage

1. Run the script:

```bash
python onkyo.pyw
```
*(Note: The `.pyw` extension runs the script without opening a console window on Windows)*

2. Open your web browser and navigate to:
   `http://localhost:8080` (or the IP address of the host machine on your network)

3. In the web interface, expand the "Configuration" panel and enter your **Receiver IP** and **Port** (default is usually `60128`).

## Security Notes

- **No Authentication**: This application does not implement user authentication. By default, it binds to `0.0.0.0`, meaning anyone on your local network can access the web interface and control your receiver. It is highly recommended to run this only on a trusted local network.
- **Private IPs Only**: The server includes an SSRF (Server-Side Request Forgery) protection mechanism that only allows sending eISCP commands to private IP addresses.

## License

MIT License
