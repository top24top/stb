
#!/usr/bin/env python3
import json
import urllib.request
import urllib.parse
import hashlib
import hmac
import time
import random
import string
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class STBAuthenticator:
    """Enhanced STB authentication with support for advanced parameters"""
    
    def __init__(self, portal_config):
        self.portal_url = portal_config['url'].rstrip('/')
        self.mac = portal_config['mac']
        self.serial_number = portal_config.get('serial_number', '')
        self.device_id = portal_config.get('device_id', '')
        self.device_id2 = portal_config.get('device_id2', '')
        self.signature = portal_config.get('signature', '')
        
        # Ensure portal URL format
        if not self.portal_url.endswith('/stalker_portal/c'):
            if self.portal_url.endswith('/stalker_portal'):
                self.portal_url = self.portal_url[:-15]  # Remove /stalker_portal
            self.portal_url += '/stalker_portal'
        else:
            self.portal_url = self.portal_url[:-2]  # Remove /c
        
        self.session_token = None
        self.token_expires = None
        
    def generate_random_string(self, length=32):
        """Generate random string for metrics"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def get_timezone_offset(self):
        """Get timezone offset in format +0000"""
        return "+0000"  # Default UTC, can be enhanced with actual timezone
    
    def build_user_agent(self):
        """Build STB user agent string"""
        return "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3"
    
    def build_x_user_agent(self):
        """Build X-User-Agent header"""
        return "Model: MAG254; Link: Ethernet,WiFi"
    
    def perform_handshake(self):
        """
        Perform handshake request as specified:
        GET "http://<SITE>/stalker_portal/server/load.php?type=stb&action=handshake&token=&JsHttpRequest=1-xml"
        """
        try:
            url = f"{self.portal_url}/server/load.php?type=stb&action=handshake&token=&JsHttpRequest=1-xml"
            
            headers = {
                'User-Agent': self.build_user_agent(),
                'Accept': 'application/json,text/javascript,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'X-User-Agent': self.build_x_user_agent(),
                'Authorization': 'Bearer',
                'Accept-Encoding': 'gzip, deflate',
                'Cookie': f'mac: {self.mac}; stb_lang: en; timezone: {self.get_timezone_offset()}'
            }
            
            logger.info(f"Performing handshake to: {url}")
            logger.debug(f"Handshake headers: {headers}")
            
            req = urllib.request.Request(url, headers=headers)
            
            with urllib.request.urlopen(req, timeout=30) as response:
                data = response.read()
                
                # Handle gzip encoding
                if response.headers.get('Content-Encoding') == 'gzip':
                    import gzip
                    data = gzip.decompress(data)
                
                response_text = data.decode('utf-8')
                logger.debug(f"Handshake response: {response_text}")
                
                # Parse JSON response
                try:
                    result = json.loads(response_text)
                    if 'js' in result and 'token' in result['js']:
                        self.session_token = result['js']['token']
                        # Set token expiration (default 24 hours)
                        self.token_expires = datetime.now() + timedelta(hours=24)
                        logger.info(f"Handshake successful, token: {self.session_token[:20]}...")
                        return result
                    else:
                        logger.error(f"No token in handshake response: {result}")
                        return None
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse handshake response: {e}")
                    return None
                    
        except Exception as e:
            logger.error(f"Handshake request failed: {e}")
            return None
    
    def perform_profile_request(self):
        """
        Perform get_profile request with enhanced authentication parameters:
        GET "http://<SITE>/stalker_portal/server/load.php?type=stb&action=get_profile&hd=1&num_banks=2&stb_type=MAG250&sn=<sn>&device_id=<id>&device_id2=<DEVENC>&signature=<SIGNENC>&auth_second_step=1&hw_version=1.7-BD-00&not_valid_token=0&metrics={...}&hw_version_2=33&api_signature=262&prehash=&JsHttpRequest=1-xml"
        """
        if not self.session_token:
            logger.error("No session token available for profile request")
            return None
            
        try:
            # Generate random string for metrics
            rand_str = self.generate_random_string()
            
            # Build metrics object
            metrics = {
                "mac": self.mac,
                "sn": self.serial_number,
                "type": "STB",
                "model": "MAG250",
                "uid": "",
                "random": rand_str
            }
            
            # Convert metrics to JSON and URL encode
            metrics_json = json.dumps(metrics, separators=(',', ':'))  # Compact JSON
            metrics_encoded = urllib.parse.quote(metrics_json)
            
            # Build URL with all parameters
            params = {
                'type': 'stb',
                'action': 'get_profile',
                'hd': '1',
                'num_banks': '2',
                'stb_type': 'MAG250',
                'sn': self.serial_number,
                'device_id': self.device_id,
                'device_id2': self.device_id2,
                'signature': self.signature,
                'auth_second_step': '1',
                'hw_version': '1.7-BD-00',
                'not_valid_token': '0',
                'metrics': metrics_encoded,
                'hw_version_2': '33',
                'api_signature': '262',
                'prehash': '',
                'JsHttpRequest': '1-xml'
            }
            
            # Build query string
            query_string = urllib.parse.urlencode(params)
            url = f"{self.portal_url}/server/load.php?{query_string}"
            
            headers = {
                'Authorization': f'Bearer {self.session_token}',
                'Referer': f'{self.portal_url}/c/index.html',
                'User-Agent': self.build_user_agent(),
                'Accept': 'application/json,text/javascript,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'X-User-Agent': self.build_x_user_agent(),
                'Cookie': f'mac: {self.mac}; adid: {self.session_token}'
            }
            
            logger.info(f"Performing profile request to: {url}")
            logger.debug(f"Profile headers: {headers}")
            
            req = urllib.request.Request(url, headers=headers)
            
            with urllib.request.urlopen(req, timeout=30) as response:
                data = response.read()
                
                # Handle gzip encoding
                if response.headers.get('Content-Encoding') == 'gzip':
                    import gzip
                    data = gzip.decompress(data)
                
                response_text = data.decode('utf-8')
                logger.debug(f"Profile response: {response_text}")
                
                # Parse JSON response
                try:
                    result = json.loads(response_text)
                    logger.info("Profile request successful")
                    return result
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse profile response: {e}")
                    return None
                    
        except Exception as e:
            logger.error(f"Profile request failed: {e}")
            return None
    
    def get_channels(self):
        """Get channels list from portal"""
        if not self.session_token:
            logger.error("No session token available for channels request")
            return None
            
        try:
            url = f"{self.portal_url}/server/load.php?type=itv&action=get_all_channels&JsHttpRequest=1-xml"
            
            headers = {
                'Authorization': f'Bearer {self.session_token}',
                'User-Agent': self.build_user_agent(),
                'X-User-Agent': self.build_x_user_agent(),
                'Cookie': f'mac: {self.mac}; adid: {self.session_token}'
            }
            
            req = urllib.request.Request(url, headers=headers)
            
            with urllib.request.urlopen(req, timeout=30) as response:
                data = response.read()
                
                # Handle gzip encoding
                if response.headers.get('Content-Encoding') == 'gzip':
                    import gzip
                    data = gzip.decompress(data)
                
                response_text = data.decode('utf-8')
                
                # Parse JSON response
                try:
                    result = json.loads(response_text)
                    channels = result.get('js', {}).get('data', [])
                    logger.info(f"Retrieved {len(channels)} channels")
                    return channels
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse channels response: {e}")
                    return None
                    
        except Exception as e:
            logger.error(f"Channels request failed: {e}")
            return None
    
    def get_stream_url(self, channel_id):
        """Get stream URL for specific channel"""
        if not self.session_token:
            logger.error("No session token available for stream request")
            return None
            
        try:
            url = f"{self.portal_url}/server/load.php?type=itv&action=create_link&cmd={channel_id}&JsHttpRequest=1-xml"
            
            headers = {
                'Authorization': f'Bearer {self.session_token}',
                'User-Agent': self.build_user_agent(),
                'X-User-Agent': self.build_x_user_agent(),
                'Cookie': f'mac: {self.mac}; adid: {self.session_token}'
            }
            
            req = urllib.request.Request(url, headers=headers)
            
            with urllib.request.urlopen(req, timeout=30) as response:
                data = response.read()
                
                # Handle gzip encoding
                if response.headers.get('Content-Encoding') == 'gzip':
                    import gzip
                    data = gzip.decompress(data)
                
                response_text = data.decode('utf-8')
                
                # Parse JSON response
                try:
                    result = json.loads(response_text)
                    stream_url = result.get('js', {}).get('cmd', '')
                    if stream_url:
                        logger.info(f"Stream URL retrieved for channel {channel_id}")
                        return stream_url
                    else:
                        logger.error(f"No stream URL in response for channel {channel_id}")
                        return None
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse stream response: {e}")
                    return None
                    
        except Exception as e:
            logger.error(f"Stream request failed: {e}")
            return None
    
    def is_token_valid(self):
        """Check if current token is still valid"""
        if not self.session_token or not self.token_expires:
            return False
        return datetime.now() < self.token_expires
    
    def authenticate(self):
        """Full authentication flow: handshake + profile"""
        logger.info("Starting STB authentication flow")
        
        # Step 1: Perform handshake
        handshake_result = self.perform_handshake()
        if not handshake_result:
            logger.error("Authentication failed at handshake step")
            return False
        
        # Step 2: Perform profile request
        profile_result = self.perform_profile_request()
        if not profile_result:
            logger.error("Authentication failed at profile step")
            return False
        
        logger.info("STB authentication completed successfully")
        return True
    
    def get_epg(self, period=7):
        """Get Electronic Program Guide for specified period (days)"""
        if not self.session_token:
            logger.error("No session token available for EPG request")
            return None
            
        try:
            url = f"{self.portal_url}/server/load.php?type=itv&action=get_epg_info&period={period}&JsHttpRequest=1-xml"
            
            headers = {
                'Authorization': f'Bearer {self.session_token}',
                'User-Agent': self.build_user_agent(),
                'X-User-Agent': self.build_x_user_agent(),
                'Cookie': f'mac: {self.mac}; adid: {self.session_token}'
            }
            
            req = urllib.request.Request(url, headers=headers)
            
            with urllib.request.urlopen(req, timeout=30) as response:
                data = response.read()
                
                # Handle gzip encoding
                if response.headers.get('Content-Encoding') == 'gzip':
                    import gzip
                    data = gzip.decompress(data)
                
                response_text = data.decode('utf-8')
                
                # Parse JSON response
                try:
                    result = json.loads(response_text)
                    epg_data = result.get('js', {})
                    logger.info(f"Retrieved EPG data for {period} days")
                    return epg_data
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse EPG response: {e}")
                    return None
                    
        except Exception as e:
            logger.error(f"EPG request failed: {e}")
            return None
    
    def get_genres(self):
        """Get available channel genres"""
        if not self.session_token:
            logger.error("No session token available for genres request")
            return None
            
        try:
            url = f"{self.portal_url}/server/load.php?type=itv&action=get_genres&JsHttpRequest=1-xml"
            
            headers = {
                'Authorization': f'Bearer {self.session_token}',
                'User-Agent': self.build_user_agent(),
                'X-User-Agent': self.build_x_user_agent(),
                'Cookie': f'mac: {self.mac}; adid: {self.session_token}'
            }
            
            req = urllib.request.Request(url, headers=headers)
            
            with urllib.request.urlopen(req, timeout=30) as response:
                data = response.read()
                
                # Handle gzip encoding
                if response.headers.get('Content-Encoding') == 'gzip':
                    import gzip
                    data = gzip.decompress(data)
                
                response_text = data.decode('utf-8')
                
                # Parse JSON response
                try:
                    result = json.loads(response_text)
                    genres = result.get('js', [])
                    logger.info(f"Retrieved {len(genres)} genres")
                    return genres
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse genres response: {e}")
                    return None
                    
        except Exception as e:
            logger.error(f"Genres request failed: {e}")
            return None
    
    def keep_alive(self):
        """Send keep-alive request to maintain session"""
        if not self.session_token:
            logger.error("No session token available for keep-alive")
            return False
            
        try:
            url = f"{self.portal_url}/server/load.php?type=watchdog&JsHttpRequest=1-xml"
            
            headers = {
                'Authorization': f'Bearer {self.session_token}',
                'User-Agent': self.build_user_agent(),
                'X-User-Agent': self.build_x_user_agent(),
                'Cookie': f'mac: {self.mac}; adid: {self.session_token}'
            }
            
            req = urllib.request.Request(url, headers=headers)
            
            with urllib.request.urlopen(req, timeout=15) as response:
                data = response.read()
                
                # Handle gzip encoding
                if response.headers.get('Content-Encoding') == 'gzip':
                    import gzip
                    data = gzip.decompress(data)
                
                response_text = data.decode('utf-8')
                
                # Parse JSON response
                try:
                    result = json.loads(response_text)
                    logger.debug("Keep-alive successful")
                    return True
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse keep-alive response: {e}")
                    return False
                    
        except Exception as e:
            logger.error(f"Keep-alive request failed: {e}")
            return False


def main():
    """Example usage of STB Authenticator"""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Example portal configuration
    portal_config = {
        'url': 'http://example.com/stalker_portal',
        'mac': '00:1A:79:XX:XX:XX',  # Replace with actual MAC
        'serial_number': 'STB123456789',  # Replace with actual serial
        'device_id': 'device123',  # Replace with actual device ID
        'device_id2': 'encoded_device_id',  # Replace with encoded device ID
        'signature': 'signature123'  # Replace with actual signature
    }
    
    # Create authenticator instance
    auth = STBAuthenticator(portal_config)
    
    # Perform authentication
    if auth.authenticate():
        print("Authentication successful!")
        
        # Get channels
        channels = auth.get_channels()
        if channels:
            print(f"Found {len(channels)} channels")
            for channel in channels[:5]:  # Show first 5 channels
                print(f"- {channel.get('name', 'Unknown')} (ID: {channel.get('id', 'N/A')})")
        
        # Get genres
        genres = auth.get_genres()
        if genres:
            print(f"Found {len(genres)} genres")
        
        # Example: Get stream URL for first channel
        if channels and len(channels) > 0:
            first_channel_id = channels[0].get('id')
            if first_channel_id:
                stream_url = auth.get_stream_url(first_channel_id)
                if stream_url:
                    print(f"Stream URL for first channel: {stream_url}")
    else:
        print("Authentication failed!")


if __name__ == "__main__":
    main()