#!/usr/bin/env python3
import json
import os
import re
import time
import urllib.parse
import urllib.request
import uuid
import hashlib
import random
import string
from datetime import datetime
from flask import Flask, request, Response, render_template, redirect, url_for, jsonify
from threading import Thread
import sqlite3
import logging

app = Flask(__name__)
app.secret_key = 'stb-proxy-secret-key'

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
CONFIG_FILE = '/config/config.json'
DB_FILE = '/config/database.db'
DEFAULT_CONFIG = {
    'host': '0.0.0.0',
    'port': 8001,
    'portals': [],
    'channels': [],
    'timezone': 'Europe/London'
}

class STBProxy:
    def __init__(self):
        self.config = self.load_config()
        self.init_database()
        
    def load_config(self):
        """Load configuration from file"""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                # Merge with defaults
                for key, value in DEFAULT_CONFIG.items():
                    if key not in config:
                        config[key] = value
                return config
            except Exception as e:
                logger.error(f"Error loading config: {e}")
                return DEFAULT_CONFIG.copy()
        return DEFAULT_CONFIG.copy()
    
    def save_config(self):
        """Save configuration to file"""
        try:
            os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving config: {e}")
    
    def init_database(self):
        """Initialize SQLite database"""
        try:
            os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            
            # Create tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS portals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    mac TEXT NOT NULL,
                    serial_number TEXT,
                    device_id TEXT,
                    device_id2 TEXT,
                    signature TEXT,
                    enabled INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS channels (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    portal_id INTEGER,
                    channel_id TEXT,
                    name TEXT,
                    custom_name TEXT,
                    number INTEGER,
                    custom_number INTEGER,
                    genre TEXT,
                    custom_genre TEXT,
                    url TEXT,
                    enabled INTEGER DEFAULT 1,
                    FOREIGN KEY (portal_id) REFERENCES portals (id)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    portal_id INTEGER,
                    token TEXT,
                    expires_at TIMESTAMP,
                    FOREIGN KEY (portal_id) REFERENCES portals (id)
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
    
    def generate_random_string(self, length=32):
        """Generate random string for metrics"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def encode_parameter(self, value):
        """URL encode parameter"""
        return urllib.parse.quote(str(value))
    
    def get_timezone_offset(self):
        """Get timezone offset"""
        # Simple timezone offset calculation
        return "+0000"  # Default to UTC, can be enhanced
    
    def make_stalker_request(self, portal_id, request_type, params=None):
        """Make authenticated request to Stalker portal"""
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM portals WHERE id = ?', (portal_id,))
            portal = cursor.fetchone()
            conn.close()
            
            if not portal:
                return None
            
            portal_data = {
                'id': portal[0],
                'name': portal[1],
                'url': portal[2],
                'mac': portal[3],
                'serial_number': portal[4],
                'device_id': portal[5],
                'device_id2': portal[6],
                'signature': portal[7]
            }
            
            if request_type == 'handshake':
                return self.handshake_request(portal_data)
            elif request_type == 'profile':
                return self.profile_request(portal_data, params)
            elif request_type == 'channels':
                return self.channels_request(portal_data, params)
            
        except Exception as e:
            logger.error(f"Error making stalker request: {e}")
            return None
    
    def handshake_request(self, portal_data):
        """Perform handshake request"""
        try:
            base_url = portal_data['url'].rstrip('/')
            if not base_url.endswith('/stalker_portal/c'):
                base_url += '/stalker_portal'
            
            url = f"{base_url}/server/load.php?type=stb&action=handshake&token=&JsHttpRequest=1-xml"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3',
                'Accept': 'application/json,text/javascript,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'X-User-Agent': 'Model: MAG254; Link: Ethernet,WiFi',
                'Authorization': 'Bearer',
                'Accept-Encoding': 'gzip, deflate',
                'Cookie': f'mac: {portal_data["mac"]}; stb_lang: en; timezone: {self.get_timezone_offset()}'
            }
            
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as response:
                data = response.read().decode('utf-8')
                return json.loads(data) if data else None
                
        except Exception as e:
            logger.error(f"Handshake request error: {e}")
            return None
    
    def profile_request(self, portal_data, token=None):
        """Perform profile request with enhanced authentication"""
        try:
            base_url = portal_data['url'].rstrip('/')
            if not base_url.endswith('/stalker_portal/c'):
                base_url += '/stalker_portal'
            
            # Generate random string for metrics
            rand_str = self.generate_random_string()
            
            # Encode parameters
            sn_enc = self.encode_parameter(portal_data['serial_number'] or '')
            dev_enc = self.encode_parameter(portal_data['device_id'] or '')
            dev2_enc = self.encode_parameter(portal_data['device_id2'] or '')
            sign_enc = self.encode_parameter(portal_data['signature'] or '')
            mac_enc = self.encode_parameter(portal_data['mac'])
            
            # Build metrics JSON
            metrics = {
                "mac": portal_data['mac'],
                "sn": portal_data['serial_number'] or '',
                "type": "STB",
                "model": "MAG250",
                "uid": "",
                "random": rand_str
            }
            metrics_str = json.dumps(metrics).replace(' ', '')
            metrics_encoded = urllib.parse.quote(metrics_str)
            
            # Build URL
            url = (f"{base_url}/server/load.php?type=stb&action=get_profile&hd=1&num_banks=2"
                   f"&stb_type=MAG250&sn={sn_enc}&device_id={dev_enc}&device_id2={dev2_enc}"
                   f"&signature={sign_enc}&auth_second_step=1&hw_version=1.7-BD-00"
                   f"&not_valid_token=0&metrics={metrics_encoded}&hw_version_2=33"
                   f"&api_signature=262&prehash=&JsHttpRequest=1-xml")
            
            headers = {
                'Authorization': f'Bearer {token or ""}',
                'Referer': f'{base_url}/c/index.html',
                'User-Agent': 'Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3',
                'Accept': 'application/json,text/javascript,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'X-User-Agent': 'Model: MAG254; Link: Ethernet,WiFi',
                'Cookie': f'mac: {portal_data["mac"]}; adid: {token or ""}'
            }
            
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as response:
                data = response.read().decode('utf-8')
                return json.loads(data) if data else None
                
        except Exception as e:
            logger.error(f"Profile request error: {e}")
            return None
    
    def channels_request(self, portal_data, token=None):
        """Get channels list"""
        try:
            base_url = portal_data['url'].rstrip('/')
            if not base_url.endswith('/stalker_portal/c'):
                base_url += '/stalker_portal'
            
            url = f"{base_url}/server/load.php?type=itv&action=get_all_channels&JsHttpRequest=1-xml"
            
            headers = {
                'Authorization': f'Bearer {token or ""}',
                'User-Agent': 'Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3',
                'Cookie': f'mac: {portal_data["mac"]}; adid: {token or ""}'
            }
            
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as response:
                data = response.read().decode('utf-8')
                return json.loads(data) if data else None
                
        except Exception as e:
            logger.error(f"Channels request error: {e}")
            return None

# Global proxy instance
proxy = STBProxy()

@app.route('/')
def index():
    """Main configuration page"""
    return render_template('index.html', config=proxy.config)

@app.route('/api/portals', methods=['GET'])
def get_portals():
    """Get all portals"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM portals ORDER BY name')
        portals = cursor.fetchall()
        conn.close()
        
        portal_list = []
        for portal in portals:
            portal_list.append({
                'id': portal[0],
                'name': portal[1],
                'url': portal[2],
                'mac': portal[3],
                'serial_number': portal[4],
                'device_id': portal[5],
                'device_id2': portal[6],
                'signature': portal[7],
                'enabled': bool(portal[8])
            })
        
        return jsonify(portal_list)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/portals', methods=['POST'])
def add_portal():
    """Add new portal"""
    try:
        data = request.get_json()
        
        required_fields = ['name', 'url', 'mac']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO portals 
            (name, url, mac, serial_number, device_id, device_id2, signature, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['name'],
            data['url'],
            data['mac'],
            data.get('serial_number', ''),
            data.get('device_id', ''),
            data.get('device_id2', ''),
            data.get('signature', ''),
            data.get('enabled', True)
        ))
        
        portal_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({'id': portal_id, 'message': 'Portal added successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/portals/<int:portal_id>', methods=['PUT'])
def update_portal(portal_id):
    """Update portal"""
    try:
        data = request.get_json()
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE portals SET 
            name=?, url=?, mac=?, serial_number=?, device_id=?, device_id2=?, signature=?, enabled=?
            WHERE id=?
        ''', (
            data['name'],
            data['url'],
            data['mac'],
            data.get('serial_number', ''),
            data.get('device_id', ''),
            data.get('device_id2', ''),
            data.get('signature', ''),
            data.get('enabled', True),
            portal_id
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Portal updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/portals/<int:portal_id>', methods=['DELETE'])
def delete_portal(portal_id):
    """Delete portal"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM portals WHERE id=?', (portal_id,))
        cursor.execute('DELETE FROM channels WHERE portal_id=?', (portal_id,))
        cursor.execute('DELETE FROM sessions WHERE portal_id=?', (portal_id,))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Portal deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/portals/<int:portal_id>/test', methods=['POST'])
def test_portal(portal_id):
    """Test portal connection"""
    try:
        # Test handshake
        handshake_result = proxy.make_stalker_request(portal_id, 'handshake')
        if not handshake_result:
            return jsonify({'success': False, 'message': 'Handshake failed'})
        
        # Extract token from handshake
        token = handshake_result.get('js', {}).get('token', '')
        
        # Test profile request
        profile_result = proxy.make_stalker_request(portal_id, 'profile', token)
        if not profile_result:
            return jsonify({'success': False, 'message': 'Profile request failed'})
        
        return jsonify({
            'success': True, 
            'message': 'Portal test successful',
            'token': token
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/portals/<int:portal_id>/channels', methods=['GET'])
def get_portal_channels(portal_id):
    """Get channels for specific portal"""
    try:
        # First get or create session
        handshake_result = proxy.make_stalker_request(portal_id, 'handshake')
        if not handshake_result:
            return jsonify({'error': 'Failed to connect to portal'}), 500
        
        token = handshake_result.get('js', {}).get('token', '')
        
        # Get profile to ensure authentication
        profile_result = proxy.make_stalker_request(portal_id, 'profile', token)
        if not profile_result:
            return jsonify({'error': 'Authentication failed'}), 500
        
        # Get channels
        channels_result = proxy.make_stalker_request(portal_id, 'channels', token)
        if not channels_result:
            return jsonify({'error': 'Failed to get channels'}), 500
        
        channels = channels_result.get('js', {}).get('data', [])
        return jsonify(channels)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/m3u')
def generate_m3u():
    """Generate M3U playlist"""
    try:
        m3u_content = "#EXTM3U\n"
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM portals WHERE enabled = 1')
        portals = cursor.fetchall()
        
        for portal in portals:
            portal_id = portal[0]
            portal_name = portal[1]
            
            # Get channels for this portal
            cursor.execute('SELECT * FROM channels WHERE portal_id = ? AND enabled = 1', (portal_id,))
            channels = cursor.fetchall()
            
            for channel in channels:
                channel_name = channel[4] or channel[3]  # custom_name or name
                channel_number = channel[6] or channel[5]  # custom_number or number
                channel_genre = channel[8] or channel[7]  # custom_genre or genre
                
                m3u_content += f'#EXTINF:-1 tvg-id="{channel[2]}" tvg-name="{channel_name}" '
                m3u_content += f'tvg-logo="" group-title="{channel_genre}",{channel_name}\n'
                m3u_content += f"{request.url_root}stream/{portal_id}/{channel[2]}\n"
        
        conn.close()
        
        return Response(m3u_content, mimetype='text/plain')
    except Exception as e:
        return Response(f"Error generating M3U: {e}", status=500)

@app.route('/stream/<int:portal_id>/<channel_id>')
def stream_channel(portal_id, channel_id):
    """Stream channel"""
    try:
        # Get authentication token
        handshake_result = proxy.make_stalker_request(portal_id, 'handshake')
        if not handshake_result:
            return Response("Authentication failed", status=500)
        
        token = handshake_result.get('js', {}).get('token', '')
        
        # Get stream URL
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT url FROM portals WHERE id = ?', (portal_id,))
        portal = cursor.fetchone()
        conn.close()
        
        if not portal:
            return Response("Portal not found", status=404)
        
        base_url = portal[0].rstrip('/')
        if not base_url.endswith('/stalker_portal/c'):
            base_url += '/stalker_portal'
        
        # Create stream URL
        stream_url = f"{base_url}/server/load.php?type=itv&action=create_link&cmd={channel_id}&JsHttpRequest=1-xml"
        
        # Proxy the stream
        headers = {
            'Authorization': f'Bearer {token}',
            'User-Agent': 'Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3'
        }
        
        req = urllib.request.Request(stream_url, headers=headers)
        with urllib.request.urlopen(req) as response:
            stream_data = json.loads(response.read().decode('utf-8'))
            actual_stream_url = stream_data.get('js', {}).get('cmd', '')
            
            if actual_stream_url:
                return redirect(actual_stream_url)
            else:
                return Response("Stream URL not found", status=404)
                
    except Exception as e:
        logger.error(f"Stream error: {e}")
        return Response(f"Stream error: {e}", status=500)

if __name__ == '__main__':
    host = proxy.config.get('host', '0.0.0.0')
    port = proxy.config.get('port', 8001)
    app.run(host=host, port=port, debug=True)