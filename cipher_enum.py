import sys
import ssl
import socket
import json

def test_tls12_ciphers(host, port, allowed_ciphers_tls12):
    print("=== TLSv1.2 ===")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    for cipher in allowed_ciphers_tls12:
        try:
            context.set_ciphers(cipher)
        except ssl.SSLError:
            print(f"Invalid cipher for TLSv1.2: {cipher}")
            continue

        try:
            with socket.create_connection((host, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    print(f"Supported: {cipher}")
        except Exception:
            print(f"Not supported: {cipher}")

def test_tls13_ciphers(host, port, allowed_ciphers_tls13):
    print("\n=== TLSv1.3 ===")
    # TLS 1.3 ciphers cannot be set individually in Python SSLContext.
    # Instead, test if TLS 1.3 is supported at all by connecting with TLS 1.3 only.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                # If connection succeeds, TLS 1.3 is supported.
                print("TLS 1.3 is supported (specific cipher detection not available in Python ssl).")
    except Exception as e:
        print(f"TLS 1.3 connection failed: {e}")

def get_server_supported_ciphers(host, port, min_version, max_version):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = min_version
    context.maximum_version = max_version
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Gather all ciphers from the underlying OpenSSL version
    ciphers = [c['name'] for c in context.get_ciphers()]
    supported = []

    for cipher in ciphers:
        try:
            context.set_ciphers(cipher)
        except ssl.SSLError:
            continue

        try:
            with socket.create_connection((host, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    supported.append(cipher)
        except Exception:
            pass

    return supported

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <host> <port> <allowed_ciphers_json>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    allowed_ciphers_file = sys.argv[3]

    try:
        with open(allowed_ciphers_file, 'r') as f:
            allowed_ciphers = json.load(f)
    except Exception as e:
        print(f"Error loading allowed ciphers JSON file: {e}")
        sys.exit(1)

    print(f"Testing ciphers on {host}:{port}\n")

    allowed_tls12 = allowed_ciphers.get("TLSv1.2", [])
    allowed_tls13 = allowed_ciphers.get("TLSv1.3", [])

    test_tls12_ciphers(host, port, allowed_tls12)
    test_tls13_ciphers(host, port, allowed_tls13)

    print("\n=== Checking for ciphers supported by server but NOT in allowed list ===")

    server_tls12 = get_server_supported_ciphers(host, port, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)
    disallowed_tls12 = [c for c in server_tls12 if c not in allowed_tls12]
    print("\n-- TLSv1.2 unexpected supported ciphers --")
    for c in disallowed_tls12:
        print(c)

    # For TLS 1.3, Python ssl does not provide ciphers enumeration, so only check if TLS1.3 is supported
    # You can implement external tools like `openssl s_client` for detailed TLS 1.3 ciphers enumeration

if __name__ == "__main__":
    main()
