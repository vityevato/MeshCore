#!/usr/bin/env python3
"""
Upload CA certificate to MeshCore device via Serial CLI
Usage: python3 upload_cert.py /dev/cu.usbserial-0001 mqtt_ca.crt
"""

import sys
import serial
import time

def upload_certificate(port, cert_file):
    """Upload certificate line by line via Serial"""
    
    # Open serial connection
    ser = serial.Serial(port, 115200, timeout=2)
    time.sleep(0.5)
    
    # Clear any pending data
    ser.reset_input_buffer()
    
    print(f"Uploading {cert_file} to {port}...")
    
    # Start upload
    ser.write(b"set mqtt.cert.upload BEGIN\r")
    time.sleep(2.0)  # Wait for response
    
    # Read all available lines and find the response
    found_ok = False
    for i in range(100):
        line = ser.readline().decode('utf-8', errors='ignore').strip()
        if line:
            # Look for our command response (format: "  -> OK - ready to receive")
            if "ready to receive" in line:
                print("✓ Upload started")
                found_ok = True
                break
            elif ("Error" in line or "error" in line) and ("upload" in line or "opening" in line):
                print(f"✗ Error: {line}")
                break
    
    if not found_ok:
        print("ERROR: Failed to start upload (no response)")
        ser.close()
        return False
    
    # Upload certificate line by line
    print("Uploading certificate lines...")
    with open(cert_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.rstrip('\n\r')
            if not line:
                continue
                
            cmd = f"set mqtt.cert.upload {line}\r"
            ser.write(cmd.encode('utf-8'))
            time.sleep(0.1)
            
            # Read response but don't print
            ser.readline()
    
    # Finish upload
    ser.write(b"set mqtt.cert.upload END\r")
    time.sleep(1.0)
    
    found_saved = False
    for _ in range(20):
        line = ser.readline().decode('utf-8', errors='ignore').strip()
        if line:
            if "certificate saved" in line:
                found_saved = True
                break
    
    # Verify
    ser.write(b"get mqtt.cert.status\r")
    time.sleep(1.0)
    
    found_ca = False
    for _ in range(20):
        line = ser.readline().decode('utf-8', errors='ignore').strip()
        if line and "CA:" in line:
            if "CA: YES" in line:
                found_ca = True
            break
    
    ser.close()
    
    if found_saved or found_ca:
        print("\n✅ Certificate uploaded successfully!")
        return True
    else:
        print("\n❌ Upload failed!")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 upload_cert.py <serial_port> <cert_file>")
        print("Example: python3 upload_cert.py /dev/cu.usbserial-0001 mqtt_ca.crt")
        sys.exit(1)
    
    port = sys.argv[1]
    cert_file = sys.argv[2]
    
    success = upload_certificate(port, cert_file)
    sys.exit(0 if success else 1)
