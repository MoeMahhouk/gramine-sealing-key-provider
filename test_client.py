import socket
import json
import struct
import sys
import hashlib
import binascii

class SGXQuoteConstants:
    HEADER_SIZE = 48
    REPORT_BODY_OFFSET = HEADER_SIZE
    REPORT_BODY_SIZE = 384
    REPORT_DATA_OFFSET = REPORT_BODY_OFFSET + 320  # Report data is 64 bytes, towards end of report body
    REPORT_DATA_SIZE = 64

def hex_print(label, data):
    """Helper function to print hex data with label"""
    if isinstance(data, list):
        data = bytes(data)
    elif isinstance(data, str):
        data = bytes.fromhex(data)
    print(f"{label}:\n  Length: {len(data)} bytes\n  Hex: {data.hex()}")

def calculate_hash(data):
    """Calculate SHA256 hash of data"""
    if isinstance(data, list):
        data = bytes(data)
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.digest()

def extract_report_data(quote):
    """Extract report data from SGX quote"""
    try:
        # Report data is 64 bytes at offset 320 in the report body
        # Report body starts after the quote header
        report_data = quote[SGXQuoteConstants.REPORT_DATA_OFFSET:
                          SGXQuoteConstants.REPORT_DATA_OFFSET + SGXQuoteConstants.REPORT_DATA_SIZE]
        
        # First 32 bytes contain our hash
        return report_data[:32]
    except Exception as e:
        print(f"Error extracting report data: {e}")
        return None

def verify_response(encrypted_key, provider_quote):
    """Verify the response by checking hash in quote's report data"""
    try:
        # Calculate hash of encrypted key
        calculated_hash = calculate_hash(encrypted_key)
        hex_print("Calculated hash of encrypted key", calculated_hash)

        # Extract report data from quote
        stored_hash = extract_report_data(provider_quote)
        if stored_hash is None:
            print("Failed to extract report data from quote")
            return False
            
        hex_print("Hash from quote's report data", stored_hash)

        # Compare hashes
        if calculated_hash == stored_hash:
            print("\nHash verification: SUCCESS")
            return True
        else:
            print("\nHash verification: FAILED")
            return False

    except Exception as e:
        print(f"\nVerification error: {e}")
        return False

def send_quote(host='localhost', port=3443, quote_path='quotes/tdxQuote.txt'):
    print(f"\nReading quote from: {quote_path}")
    
    # Read the quote file
    with open(quote_path, 'rb') as f:
        quote_data = f.read()
    
    hex_print("Input quote", quote_data)
    
    # Create request
    request = {
        'quote': list(quote_data)  # Convert bytes to list for JSON serialization
    }
    
    # Serialize request
    request_json = json.dumps(request).encode()
    
    print("\nConnecting to server...")
    # Connect and send
    with socket.create_connection((host, port)) as sock:
        print(f"Connected to {host}:{port}")
        
        # Send length
        sock.send(struct.pack('>I', len(request_json)))
        # Send data
        sock.send(request_json)
        print("Quote sent, waiting for response...")
        
        # Read response length
        resp_len = struct.unpack('>I', sock.recv(4))[0]
        print(f"Expected response length: {resp_len} bytes")
        
        # Read response
        response = sock.recv(resp_len)
        
        # Parse response
        resp_data = json.loads(response)
        
        print("\nResponse received:")
        encrypted_key = bytes(resp_data['encrypted_key'])
        provider_quote = bytes(resp_data['provider_quote'])
        
        hex_print("Encrypted key", encrypted_key)
        hex_print("Provider quote", provider_quote)
        
        print("\nVerifying response...")
        verify_response(encrypted_key, provider_quote)

def main():
    # Parse command line arguments
    if len(sys.argv) > 1:
        quote_path = sys.argv[1]
    else:
        quote_path = 'quotes/tdxQuote.txt'
        print(f"No quote path provided, using default: {quote_path}")

    try:
        send_quote(quote_path=quote_path)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()

