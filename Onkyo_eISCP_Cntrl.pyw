# Import necessary libraries
from flask import Flask, request, jsonify, Response, abort
import socket
import struct
import ipaddress
import re
import logging
import time
from collections import deque, defaultdict
from functools import wraps
from waitress import serve

# --- Configuration ---
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 8080
RECEIVER_TIMEOUT = 3 # Increased timeout for queries
MAX_CONTENT_LENGTH = 16 * 1024 # Limit request body to 16KB

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- Security: Rate Limiter ---
class RateLimiter:
    def __init__(self, limit=10, window=1):
        self.limit = limit
        self.window = window
        self.clients = defaultdict(lambda: deque())

    def is_allowed(self, ip):
        now = time.time()
        timestamps = self.clients[ip]
        
        # Remove old timestamps
        while timestamps and timestamps[0] <= now - self.window:
            timestamps.popleft()
            
        if len(timestamps) < self.limit:
            timestamps.append(now)
            return True
        return False

limiter = RateLimiter(limit=10, window=1)

def limit_rate(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not limiter.is_allowed(request.remote_addr):
            logger.warning(f"Rate limit exceeded for IP: {request.remote_addr}")
            return jsonify({"error": "Too many requests"}), 429
        return f(*args, **kwargs)
    return decorated_function

# --- Security Enhancement: Command Allowlist ---
ALLOWED_COMMANDS = {
    'PWR': re.compile(r'^(00|01)$'),
    'MVL': re.compile(r'^(UP|DOWN|[0-7][0-9A-F])$'),
    'AMT': re.compile(r'^(TG|00|01)$'),
    'SLI': re.compile(r'^[0-9A-F]{2}$'),
    'LMD': re.compile(r'^[0-9A-F]{2}$'),
    'SWL': re.compile(r'^(UP|DOWN|00|[+\-][0-9A-F])$'),
    'CTL': re.compile(r'^(UP|DOWN|00|[+\-][0-9A-F])$'),
    'TFR': re.compile(r'^(BUP|BDOWN|TUP|TDOWN|[BT](00|[+\-][0-9A-F]))$'),
}

# --- New Security: Query Allowlist ---
ALLOWED_QUERIES = {
    'PWR', # Power status
    'MVL', # Master Volume
    'AMT', # Mute status
    'SLI', # Input selector
    'LMD', # Listening Mode
    'SWL', # Subwoofer Level
    'CTL', # Center Level
    'TFR', # Tone (Bass/Treble)
}

# --- Flask App Setup ---
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com;"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# --- HTML Interface Content ---
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Onkyo Controller</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
      body { font-family: 'Poppins', sans-serif; }
      .loader {
        border: 4px solid rgba(255, 255, 255, 0.2);
        border-top: 4px solid #c084fc; /* purple-400 */
        border-radius: 50%;
        width: 20px;
        height: 20px;
        animation: spin 1s linear infinite;
        display: inline-block;
        margin-left: 8px;
        vertical-align: middle;
      }
      @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
      .hidden { display: none; }
      @keyframes pulse-bg {
        0%, 100% { transform: scale(1); opacity: 1; }
        50% { transform: scale(0.95); opacity: 0.7; }
      }
      .animate-pulse-bg { animation: pulse-bg 0.4s ease-out; }
      input[type=range] {
        height: 24px;
        -webkit-appearance: none;
        margin: 10px 0;
        width: 100%;
        background: transparent;
        cursor: pointer;
      }
      input[type=range]:focus { outline: none; }
      input[type=range]::-webkit-slider-runnable-track {
        width: 100%;
        height: 8px;
        cursor: pointer;
        background: rgba(55, 65, 81, 0.8); /* gray-700 */
        border-radius: 4px;
      }
      input[type=range]::-moz-range-track {
        width: 100%;
        height: 8px;
        cursor: pointer;
        background: rgba(55, 65, 81, 0.8); /* gray-700 */
        border-radius: 4px;
      }
      input[type=range]::-webkit-slider-thumb {
        height: 20px;
        width: 20px;
        border-radius: 50%;
        background: #c084fc; /* purple-400 */
        cursor: pointer;
        -webkit-appearance: none;
        margin-top: -6px;
        box-shadow: 0 2px 5px rgba(0,0,0,0.3);
        transition: background-color 0.15s ease-in-out;
      }
      input[type=range]::-moz-range-thumb {
        height: 20px;
        width: 20px;
        border-radius: 50%;
        background: #c084fc; /* purple-400 */
        cursor: pointer;
        border: none;
        box-shadow: 0 2px 5px rgba(0,0,0,0.3);
        transition: background-color 0.15s ease-in-out;
      }
      input[type=range]:hover::-webkit-slider-thumb,
      input[type=range]:hover::-moz-range-thumb { background: #d8b4fe; } /* purple-300 */
      .control-button {
        transition: all 0.15s ease-in-out;
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.1);
        border: 1px solid rgba(255, 255, 255, 0.1);
        font-weight: 600;
        border-radius: 0.5rem;
        padding: 0.5rem 0.75rem;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        color: white;
      }
      .control-button:hover {
        transform: translateY(-1px) scale(1.02);
        box-shadow: 0 6px 12px -2px rgba(0, 0, 0, 0.2);
        border-color: rgba(255, 255, 255, 0.3);
      }
      .control-button:active {
        transform: translateY(0px) scale(1);
        box-shadow: inset 0 2px 4px rgba(0,0,0,0.2);
      }
      .btn-green { background-color: #22c55e; }
      .btn-green:hover { background-color: #16a34a; }
      .btn-red { background-color: #ef4444; }
      .btn-red:hover { background-color: #dc2626; }
      .btn-yellow { background-color: #eab308; }
      .btn-yellow:hover { background-color: #ca8a04; }
      .btn-gray { background-color: #6b7280; }
      .btn-gray:hover { background-color: #4b5563; }
      .btn-indigo { background-color: #9333ea; } /* purple-600 */
      .btn-indigo:hover { background-color: #7e22ce; } /* purple-700 */
      .btn-teal { background-color: #9333ea; } /* purple-600 */
      .btn-teal:hover { background-color: #7e22ce; } /* purple-700 */
      .glass-panel {
        background: rgba(31, 41, 55, 0.5); /* gray-800 @ 50% */
        backdrop-filter: blur(12px);
        border-radius: 1rem;
        border: 1px solid rgba(55, 65, 81, 1); /* gray-700 */
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.2);
        padding: 1.5rem;
      }
      #statusBox {
        position: fixed;
        top: 1.5rem;
        right: 1.5rem;
        width: auto;
        max-width: 300px;
        z-index: 50;
        border-radius: 0.75rem;
        padding: 0.75rem 1rem;
        font-size: 0.875rem;
        font-weight: 500;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        transition: all 0.3s ease-in-out;
        opacity: 0;
        transform: translateX(100%);
      }
      #statusBox.show { opacity: 1; transform: translateX(0); }
      .status-success {
        background-color: rgba(34, 197, 94, 0.8);
        backdrop-filter: blur(5px);
        color: white;
        border: 1px solid rgba(74, 222, 128, 0.5);
      }
      .status-error {
        background-color: rgba(239, 68, 68, 0.8);
        backdrop-filter: blur(5px);
        color: white;
        border: 1px solid rgba(248, 113, 113, 0.5);
      }
    </style>
</head>
<body class="bg-black text-gray-200 font-sans p-4 md:p-8 min-h-screen flex items-center justify-center">
    <div id="statusBox" class="hidden">Status Message</div>
    <div class="max-w-md w-full space-y-6">
        
        <div class="flex justify-center items-center mb-8 gap-4">
            <h1 class="text-4xl font-bold text-white tracking-tight">Onkyo Remote</h1>
            <button onclick="fetchInitialState()" title="Refresh Status" class="control-button btn-gray p-2">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="w-5 h-5">
                  <path fill-rule="evenodd" d="M15.312 11.424a5.5 5.5 0 0 1-9.2 1.34l.005-.005-1.414 1.414A7.5 7.5 0 1 0 17.5 10a7.51 7.51 0 0 0-2.188-5.025V6.5a.75.75 0 0 0 1.5 0V3.342a.75.75 0 0 0-.75-.75H12.5a.75.75 0 0 0 0 1.5h1.688A5.5 5.5 0 0 1 15.312 11.424Z" clip-rule="evenodd" />
                </svg>
            </button>
        </div>
        
        <details class="glass-panel">
            <summary class="text-lg font-semibold text-gray-100 cursor-pointer hover:text-white flex justify-between items-center">
                Configuration <span class="text-sm text-gray-400">Expand</span>
            </summary>
            <div class="mt-4 pt-4 border-t border-white/10 space-y-3">
                <div>
                    <label for="receiverIp" class="block text-sm font-medium text-gray-300 mb-1">Receiver IP:</label>
                    <input type="text" id="receiverIp" placeholder="e.g., 192.168.0.139" value="192.168.0.139" 
                           class="w-full px-3 py-2 border border-gray-700 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-purple-400 text-sm bg-gray-800/60 text-white placeholder-gray-400">
                </div>
                <div>
                    <label for="receiverPort" class="block text-sm font-medium text-gray-300 mb-1">Receiver Port:</label>
                    <input type="number" id="receiverPort" value="60128" 
                           class="w-full px-3 py-2 border border-gray-700 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-purple-400 text-sm bg-gray-800/60 text-white">
                </div>
            </div>
        </details>
        
        <div id="loadingIndicator" class="text-center hidden">
            <span class="loader"></span> <span class="text-gray-400">Processing...</span>
        </div>
        
        <div class="space-y-6">
            <div class="glass-panel flex justify-around items-center gap-4">
                <button onclick="sendCommand('PWR', '01')" class="control-button btn-green flex-1">Power On</button>
                <button onclick="sendCommand('PWR', '00')" class="control-button btn-red flex-1">Power Off</button>
            </div>
            
            <div class="glass-panel space-y-4">
                <div class="flex justify-between items-center">
                    <h3 class="text-lg font-semibold text-gray-100">Master Volume</h3>
                    <span id="volumeValue" class="text-xl font-bold text-purple-400 bg-white/10 px-3 py-1 rounded-lg">25</span>
                </div>
                <input type="range" id="volumeSlider" min="0" max="60" value="25" class="w-full">
                <div class="flex justify-center gap-4 pt-2">
                    <button onclick="sendCommand('AMT', 'TG')" title="Toggle Mute" class="control-button btn-yellow">Mute Toggle</button>
                    <button onclick="sendCommand('AMT', '00')" title="Unmute" class="control-button btn-gray">Unmute</button>
                </div>
            </div>

            <div class="glass-panel space-y-4">
                <h3 class="text-lg font-semibold text-gray-100 mb-2">Audio Levels (Tone Control)</h3>
                <p class="text-xs text-gray-400 mb-4">Hinweis: Funktioniert nur in Modi wie Stereo oder Surround, nicht im 'Direct' Modus.</p>
                
                <div class="flex justify-between items-center">
                    <label for="tfbSlider" class="font-medium text-gray-300">Bass (Front)</label>
                    <span id="tfbValue" class="text-lg font-bold text-purple-400 bg-white/10 px-3 py-0.5 rounded-lg">0 dB</span>
                </div>
                <input type="range" id="tfbSlider" min="-10" max="10" step="2" value="0" class="w-full">

                <div class="flex justify-between items-center mt-2">
                    <label for="tfrSlider" class="font-medium text-gray-300">Treble (Front)</label>
                    <span id="tfrValue" class="text-lg font-bold text-purple-400 bg-white/10 px-3 py-0.5 rounded-lg">0 dB</span>
                </div>
                <input type="range" id="tfrSlider" min="-10" max="10" step="2" value="0" class="w-full">

                <div class="flex justify-between items-center mt-2">
                    <label for="swlSlider" class="font-medium text-gray-300">Subwoofer</label>
                    <span id="swlValue" class="text-lg font-bold text-purple-400 bg-white/10 px-3 py-0.5 rounded-lg">0 dB</span>
                </div>
                <input type="range" id="swlSlider" min="-15" max="12" value="0" class="w-full">
                
                <div class="flex justify-between items-center mt-2">
                    <label for="ctlSlider" class="font-medium text-gray-300">Center</label>
                    <span id="ctlValue" class="text-lg font-bold text-purple-400 bg-white/10 px-3 py-0.5 rounded-lg">0 dB</span>
                </div>
                <input type="range" id="ctlSlider" min="-12" max="12" value="0" class="w-full">
            </div>
            
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div class="glass-panel">
                    <h3 class="text-lg font-semibold text-gray-100 mb-4 text-center">Input Source</h3>
                    <div class="grid grid-cols-2 gap-3">
                        <button onclick="sendCommand('SLI', '2B')" class="control-button btn-indigo text-sm">NET</button>
                        <button onclick="sendCommand('SLI', '23')" class="control-button btn-indigo text-sm">TV/CD</button>
                        <button onclick="sendCommand('SLI', '01')" class="control-button btn-indigo text-sm">BD/DVD</button>
                        <button onclick="sendCommand('SLI', '02')" class="control-button btn-indigo text-sm">CBL/SAT</button>
                        <button onclick="sendCommand('SLI', '05')" class="control-button btn-indigo text-sm">GAME</button>
                    </div>
                </div>
                
                <div class="glass-panel">
                    <h3 class="text-lg font-semibold text-gray-100 mb-4 text-center">Listening Mode</h3>
                    <div class="grid grid-cols-2 gap-3">
                        <button onclick="handleModeClick(this, 'LMD', '00')" class="control-button btn-teal text-sm">Stereo</button>
                        <button onclick="handleModeClick(this, 'LMD', '01')" class="control-button btn-teal text-sm">Direct</button>
                        <button onclick="handleModeClick(this, 'LMD', '02')" class="control-button btn-teal text-sm">Surround</button>
                        <button onclick="handleModeClick(this, 'LMD', '43')" class="control-button btn-teal text-sm">PLII Movie</button>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        const statusBox = document.getElementById('statusBox');
        const loadingIndicatorEl = document.getElementById('loadingIndicator');
        let statusTimeout;

        // --- Slider & Value Span References ---
        const volumeSlider = document.getElementById('volumeSlider');
        const volumeValueSpan = document.getElementById('volumeValue');
        const swlSlider = document.getElementById('swlSlider');
        const swlValueSpan = document.getElementById('swlValue');
        const ctlSlider = document.getElementById('ctlSlider');
        const ctlValueSpan = document.getElementById('ctlValue');
        const tfrSlider = document.getElementById('tfrSlider');
        const tfrValueSpan = document.getElementById('tfrValue');
        const tfbSlider = document.getElementById('tfbSlider');
        const tfbValueSpan = document.getElementById('tfbValue');

        // --- UI Feedback Functions ---
        function showStatus(message, isError = false) {
            if (!statusBox) return;
            statusBox.textContent = message;
            statusBox.classList.remove('status-success', 'status-error');
            statusBox.classList.add(isError ? 'status-error' : 'status-success');
            statusBox.classList.remove('hidden');
            statusBox.classList.add('show');
            if (statusTimeout) clearTimeout(statusTimeout);
            statusTimeout = setTimeout(() => statusBox.classList.remove('show'), 4000);
        }

        function setLoading(isLoading) {
            loadingIndicatorEl.classList.toggle('hidden', !isLoading);
        }

        function animateButton(buttonElement) {
            if (!buttonElement) return;
            buttonElement.classList.add('animate-pulse-bg');
            setTimeout(() => buttonElement.classList.remove('animate-pulse-bg'), 400);
        }
        
        function handleModeClick(buttonElement, command, parameter) {
            animateButton(buttonElement);
            sendCommand(command, parameter);
        }

        // --- Value Formatting: JS -> Receiver ---
        function decToHexVolume(dec) {
            const receiverVol = Math.round(parseInt(dec, 10) * 80 / 60);
            return receiverVol.toString(16).toUpperCase().padStart(2, '0');
        }

        function decToHexBass(dec) {
            const val = parseInt(dec, 10);
            const absVal = Math.abs(val);
            const hexDigit = absVal.toString(16).toUpperCase();
            if (val === 0) {
                return 'B00';
            }
            const sign = val > 0 ? '+' : '-';
            return 'B' + sign + hexDigit;
        }

        function decToHexTreble(dec) {
            const val = parseInt(dec, 10);
            const absVal = Math.abs(val);
            const hexDigit = absVal.toString(16).toUpperCase();
            if (val === 0) {
                return 'T00';
            }
            const sign = val > 0 ? '+' : '-';
            return 'T' + sign + hexDigit;
        }

        function decToHexLevel(dec) {
            const val = parseInt(dec, 10);
            if (val === 0) return '00';
            const sign = val > 0 ? '+' : '-';
            const hexVal = Math.abs(val).toString(16).toUpperCase();
            return sign + hexVal;
        }

        function formatDBLabel(valStr) {
            const val = parseInt(valStr, 10);
            if (val > 0) return `+${val} dB`;
            return `${val} dB`;
        }
        
        // --- Value Formatting: Receiver -> JS (NEW) ---
        
        function hexVolumeToDec(hexVal) {
            const dec = parseInt(hexVal, 16);
            if (isNaN(dec)) return 25; // Default on parse error
            // Map Onkyo volume (0-80) to our slider (0-60)
            return Math.round((dec / 80) * 60);
        }
        
        function hexLevelToDec(hexVal) {
            if (hexVal === '00' || hexVal === 'N/A') return 0;
            const sign = hexVal.startsWith('+') ? 1 : -1;
            const dec = parseInt(hexVal.substring(1), 16);
            if (isNaN(dec)) return 0;
            return dec * sign;
        }

        function parseToneResponse(tfrValue) { // tfrValue is like "B+2T-4"
            const bassMatch = tfrValue.match(/B([+\-0-9A-F]{2,3})/);
            const trebleMatch = tfrValue.match(/T([+\-0-9A-F]{2,3})/);
            
            const bassHex = bassMatch ? bassMatch[1] : '00';
            const trebleHex = trebleMatch ? trebleMatch[1] : '00';
            
            return {
                bass: hexLevelToDec(bassHex),
                treble: hexLevelToDec(trebleHex)
            };
        }
        
        // --- UI Update Functions (NEW) ---
        
        function updateVolumeUI(hexVal) {
            const decVal = hexVolumeToDec(hexVal);
            volumeSlider.value = decVal;
            volumeValueSpan.textContent = Math.round(decVal);
        }
        
        function updateLevelUI(slider, span, hexVal) {
            const decVal = hexLevelToDec(hexVal);
            slider.value = decVal;
            span.textContent = formatDBLabel(decVal);
        }

        function updateToneUI(tfrValue) { // tfrValue is "B+2T-4"
            const { bass, treble } = parseToneResponse(tfrValue);
            
            tfbSlider.value = bass;
            tfbValueSpan.textContent = formatDBLabel(bass);
            
            tfrSlider.value = treble;
            tfrValueSpan.textContent = formatDBLabel(treble);
        }
        
        function updateUIWithData(message) {
            if (!message || message.length < 3) return;
            
            const cmd = message.substring(0, 3);
            const val = message.substring(3);
            
            console.log('Received data:', cmd, val);

            switch (cmd) {
                case 'MVL': // Master Volume
                    updateVolumeUI(val);
                    break;
                case 'SWL': // Subwoofer
                    updateLevelUI(swlSlider, swlValueSpan, val);
                    break;
                case 'CTL': // Center
                    updateLevelUI(ctlSlider, ctlValueSpan, val);
                    break;
                case 'TFR': // Tone (Bass/Treble)
                    updateToneUI(val);
                    break;
                case 'AMT':
                    console.log('Mute status:', val === '01' ? 'On' : 'Off');
                    break;
                case 'PWR':
                    console.log('Power status:', val === '01' ? 'On' : 'Off');
                    break;
            }
        }
        
        // --- Slider Event Listeners ---
        volumeSlider.addEventListener('input', function() {
            volumeValueSpan.textContent = this.value;
        });
        
        volumeSlider.addEventListener('change', function() {
            sendCommand('MVL', decToHexVolume(this.value));
        });

        function addAudioSliderListeners(slider, span, command, hexConverter) {
            if (!slider) return;
            slider.addEventListener('input', function() {
                span.textContent = formatDBLabel(this.value);
            });
            slider.addEventListener('change', function() {
                const hexValue = hexConverter(this.value);
                sendCommand(command, hexValue);
            });
            // Initialize display
            span.textContent = formatDBLabel(slider.value);
        }
        
        addAudioSliderListeners(tfbSlider, tfbValueSpan, 'TFR', decToHexBass);
        addAudioSliderListeners(tfrSlider, tfrValueSpan, 'TFR', decToHexTreble);
        addAudioSliderListeners(swlSlider, swlValueSpan, 'SWL', decToHexLevel);
        addAudioSliderListeners(ctlSlider, ctlValueSpan, 'CTL', decToHexLevel);

        // --- Network Functions ---

        async function sendCommand(command, parameter) {
            const receiverIp = document.getElementById('receiverIp').value;
            const receiverPort = document.getElementById('receiverPort').value;
            
            if (!receiverIp || !receiverPort) {
                showStatus('Error: Please configure Receiver IP and Port.', true);
                return;
            }
            
            const isSliderCommand = ['MVL', 'SWL', 'CTL', 'TFR'].includes(command);
            const showLoader = !isSliderCommand;
            
            if (showLoader) setLoading(true);
            
            try {
                const response = await fetch('/send_command', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ip: receiverIp,
                        port: parseInt(receiverPort, 10),
                        command: command,
                        parameter: parameter
                    }),
                });
                
                if (showLoader) setLoading(false);
                const result = await response.json();
                
                if (response.ok) {
                    if (showLoader) {
                        showStatus(result.message || 'Command sent.', false);
                    }
                } else {
                    console.error('Backend error:', response.status, result);
                    showStatus('Error: ' + (result.error || response.statusText), true);
                }
            } catch (error) {
                if (showLoader) setLoading(false);
                console.error('Network error:', error);
                showStatus('Error: Connection failed. (' + error.message + ')', true);
            }
        }

        async function queryReceiver(command) {
            const receiverIp = document.getElementById('receiverIp').value;
            const receiverPort = document.getElementById('receiverPort').value;
            
            try {
                const response = await fetch('/query_command', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ip: receiverIp,
                        port: parseInt(receiverPort, 10),
                        command: command
                    }),
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    return result.message; // e.g., "MVL3A"
                } else {
                    console.error('Query error:', result.error);
                    showStatus(`Query failed for ${command}: ${result.error}`, true);
                    return null;
                }
            } catch (error) {
                console.error('Query network error:', error);
                showStatus(`Query failed for ${command}: ${error.message}`, true);
                return null;
            }
        }
        
        async function fetchInitialState() {
            console.log('Fetching initial state from receiver...');
            setLoading(true);
            
            const queries = ['MVL', 'SWL', 'CTL', 'TFR', 'PWR', 'AMT'];
            const results = await Promise.all(
                queries.map(cmd => queryReceiver(cmd))
            );
            
            setLoading(false);
            
            let allFailed = true;
            results.forEach(message => {
                if (message) {
                    allFailed = false;
                    updateUIWithData(message);
                }
            });
            
            if (!allFailed) {
                showStatus('Receiver state synced.', false);
            } else {
                console.log('Failed to sync any state.');
                // Don't show an error if it was just a timeout on an offline receiver
            }
        }

        // --- Page Load ---
        window.onload = fetchInitialState;
        
    </script>
</body>
</html>
"""

# --- New Helper Function ---
def parse_eiscp_response(data: bytes) -> str | None:
    """Parses a raw eISCP response and returns the core ISCP message."""
    try:
        # Find the ISCP start
        iscp_start = data.find(b'!1')
        if iscp_start == -1:
            logger.error("Parse Error: '!1' not found in response.")
            return None
        
        # Find the end of the message (CR or EOF)
        iscp_end = data.find(b'\r', iscp_start)
        if iscp_end == -1:
            iscp_end = len(data) # Use end of data if \r not found
        
        # Extract the message, e.g., "!1MVL3A"
        iscp_message = data[iscp_start:iscp_end].decode('ascii')
        
        # Return just the command + parameter, e.g., "MVL3A"
        # Strip EOF/SUB character (\x1a) which Onkyo sometimes sends before \r
        result = iscp_message[2:].replace('\x1a', '')
        
        if not re.match(r'^[A-Z0-9+\-]+$', result):
            logger.warning(f"Invalid characters in response: {result}")
            return None
        return result
    except Exception as e:
        logger.error(f"Error parsing response: {e}, Data: {data}")
        return None

def create_eiscp_packet(iscp_command: str) -> bytes:
    """Creates a basic eISCP packet."""
    if not isinstance(iscp_command, str):
        logger.error("Error: ISCP command must be a string.")
        return None

    iscp_command = iscp_command.strip()
    if not iscp_command or len(iscp_command) < 3:
        logger.error("Error: Invalid ISCP command format.")
        return None

    try:
        iscp_message_str = f"!1{iscp_command}\r"
        iscp_message_bytes = iscp_message_str.encode('ascii')
    except Exception as e:
        logger.error(f"Error creating eISCP message: {e}")
        return None

    if iscp_message_bytes is None:
        logger.error("Error: eISCP message bytes were not created.")
        return None

    iscp_data_size = len(iscp_message_bytes)
    header = b'ISCP'
    header += struct.pack('>I', 16)
    header += struct.pack('>I', iscp_data_size)
    header += b'\x01\x00\x00\x00'
    
    return header + iscp_message_bytes

@app.route('/')
def index():
    return Response(HTML_CONTENT, mimetype='text/html')

@app.route('/send_command', methods=['POST'])
@limit_rate
def handle_command():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    receiver_ip_str = data.get('ip')
    receiver_port = data.get('port')
    command = data.get('command')
    parameter = data.get('parameter')

    if not all([receiver_ip_str, receiver_port, command, parameter]):
        return jsonify({"error": "Missing required data fields"}), 400

    try:
        ip_addr = ipaddress.ip_address(receiver_ip_str)
        if not ip_addr.is_private:
            print(f"Rejected non-private IP: {ip_addr}")
            return jsonify({"error": "Invalid target: IP must be private."}), 403
    except ValueError:
        print(f"Rejected invalid IP: {receiver_ip_str}")
        return jsonify({"error": "Invalid IP address format."}), 400

    try:
        receiver_port = int(receiver_port)
        if not (1 <= receiver_port <= 65535):
            raise ValueError()
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid port number."}), 400

    if command not in ALLOWED_COMMANDS:
        print(f"Rejected invalid command: {command}")
        return jsonify({"error": f"Command '{command}' not allowed."}), 403
    
    if not ALLOWED_COMMANDS[command].fullmatch(parameter):
        print(f"Rejected invalid parameter '{parameter}' for '{command}'")
        return jsonify({"error": f"Invalid parameter for '{command}'."}), 403

    iscp_command_str = f"{command}{parameter}"
    
    slider_commands = ['MVL', 'SWL', 'CTL', 'TFR']
    if command not in slider_commands:
        print(f"Sending '{iscp_command_str}' to {receiver_ip_str}:{receiver_port}")

    packet = create_eiscp_packet(iscp_command_str)
    if packet is None:
        return jsonify({"error": "Failed to create eISCP packet"}), 500

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(RECEIVER_TIMEOUT)
            s.connect((receiver_ip_str, receiver_port))
            s.sendall(packet)
            # We could read the response here, but for simple commands,
            # it's faster to just send and disconnect.
        return jsonify({"message": f"Command '{iscp_command_str}' sent."}), 200
    except socket.timeout:
        error_msg = f"Connection timeout: {receiver_ip_str}:{receiver_port}"
        status_code = 504
    except socket.gaierror:
        error_msg = f"Could not resolve IP: {receiver_ip_str}"
        status_code = 400
    except ConnectionRefusedError:
        error_msg = f"Connection refused: {receiver_ip_str}:{receiver_port}"
        status_code = 503
    except Exception as e:
        error_msg = f"Unexpected error: {e}"
        status_code = 500
    
    logger.error(f"Error: {error_msg}")
    return jsonify({"error": error_msg}), status_code

# --- New Endpoint for Querying ---
@app.route('/query_command', methods=['POST'])
@limit_rate
def handle_query():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    receiver_ip_str = data.get('ip')
    receiver_port = data.get('port')
    command = data.get('command') # e.g., "MVL"

    if not all([receiver_ip_str, receiver_port, command]):
        return jsonify({"error": "Missing required data fields"}), 400

    # --- Validation ---
    try:
        ip_addr = ipaddress.ip_address(receiver_ip_str)
        if not ip_addr.is_private:
            return jsonify({"error": "Invalid target: IP must be private."}), 403
    except ValueError:
        return jsonify({"error": "Invalid IP address format."}), 400

    try:
        receiver_port = int(receiver_port)
        if not (1 <= receiver_port <= 65535):
            raise ValueError()
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid port number."}), 400
    # --- End Validation ---

    if command not in ALLOWED_QUERIES:
        print(f"Rejected invalid query: {command}")
        return jsonify({"error": f"Query '{command}' not allowed."}), 403

    iscp_command_str = f"{command}QSTN" # Append "Question"
    packet = create_eiscp_packet(iscp_command_str)
    if packet is None:
        return jsonify({"error": "Failed to create eISCP packet"}), 500

    # print(f"Querying '{iscp_command_str}' from {receiver_ip_str}:{receiver_port}")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(RECEIVER_TIMEOUT)
            s.connect((receiver_ip_str, receiver_port))
            s.sendall(packet)
            
            # --- Wait for and read the response ---
            response_data = s.recv(1024) 
            # --- End new part ---

        parsed_message = parse_eiscp_response(response_data)
        if parsed_message:
            # print(f"Received: {parsed_message}")
            return jsonify({"message": parsed_message}), 200
        else:
            print(f"Failed to parse response: {response_data}")
            return jsonify({"error": "Failed to parse response from receiver."}), 502

    except socket.timeout:
        error_msg = f"Query timeout: {receiver_ip_str}:{receiver_port}"
        status_code = 504
    except ConnectionRefusedError:
        error_msg = f"Connection refused: {receiver_ip_str}:{receiver_port}"
        status_code = 503
    except Exception as e:
        error_msg = f"Unexpected error: {e}"
        status_code = 500
    
    logger.error(f"Query Error: {error_msg}")
    return jsonify({"error": error_msg}), status_code


if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("Onkyo eISCP Web Controller - ENHANCED SECURITY VERSION")
    logger.info("=" * 60)
    logger.info(f"\nZum Starten benötigte Abhängigkeiten:")
    logger.info(f"  pip install flask waitress\n")
    logger.info(f"Server startet auf: http://{SERVER_HOST}:{SERVER_PORT}")
    logger.info(f"Browser öffnen: http://localhost:{SERVER_PORT}")
    logger.info(f"\nNEU: Receiver-Status wird beim Laden der Seite abgefragt.")
    logger.info(f"NEU: Refresh-Button zum erneuten Abfragen des Status.")
    logger.info(f"\nSTRG+C zum Beenden")
    logger.info("=" * 60)
    serve(app, host=SERVER_HOST, port=SERVER_PORT)
