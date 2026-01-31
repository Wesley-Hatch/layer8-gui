import mysql.connector
from mysql.connector import Error
import os
import socket

def test_connection():
    # Database connection details (Hostinger fallbacks from gui_app.pyw)
    DB_HOST = os.getenv('L8_DB_HOST') or '82.197.82.156'
    DB_USER = os.getenv('MYSQL_USER') or os.getenv('DB_USER') or 'u844677182_Layer8Database'
    DB_PASSWORD = os.getenv('MYSQL_PASSWORD') or os.getenv('DB_PASS') or 'Layer8WJA'
    DB_NAME = os.getenv('L8_DB_NAME') or 'u844677182_app'
    DB_PORT = os.getenv('L8_DB_PORT') or '3306'

    print("--- MySQL Connection Diagnostic ---")
    print(f"Target Host: {DB_HOST}")
    print(f"Target Port: {DB_PORT}")
    print(f"Database: {DB_NAME}")
    print(f"User: {DB_USER}")
    print("-" * 35)

    # 1. Test Network Reachability
    print(f"Checking if {DB_HOST}:{DB_PORT} is reachable...")
    try:
        sock = socket.create_connection((DB_HOST, int(DB_PORT)), timeout=5)
        sock.close()
        print("✅ Network reachability: SUCCESS")
    except Exception as e:
        print(f"❌ Network reachability: FAILED")
        print(f"   Reason: {e}")
        if DB_HOST == '127.0.0.1':
            print("   Hint: 127.0.0.1 (localhost) only works if the database is on your local machine.")
            print("   For Hostinger, you usually need a hostname like 'sqlXXX.hostinger.com'.")
        return

    # 2. Test MySQL Connection
    print("\nAttempting MySQL handshake...")
    try:
        print("Initializing connection object...")
        conn = mysql.connector.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            passwd=DB_PASSWORD,
            database=DB_NAME,
            connect_timeout=5,
            use_pure=True
        )
        print("Connection object created. Checking if connected...")

        if conn.is_connected():
            print("✅ MySQL Connection: SUCCESS!")
            db_info = conn.get_server_info()
            print(f"   Server version: {db_info}")
            cursor = conn.cursor()
            cursor.execute("SELECT DATABASE();")
            record = cursor.fetchone()
            print(f"   Connected to database: {record[0]}")
            
            # Check for table
            cursor.execute("SHOW TABLES LIKE 'user_logins';")
            table = cursor.fetchone()
            if table:
                print("   Table 'user_logins' found.")
            else:
                print("   ⚠️ Table 'user_logins' NOT found in this database.")
            
            cursor.close()
            conn.close()
        else:
            print("❌ MySQL Connection: FAILED (is_connected() returned False)")
    except Error as e:
        print(f"❌ MySQL Connection: FAILED")
        print(f"   Error Code: {e.errno}")
        print(f"   SQL State: {e.sqlstate}")
        print(f"   Message: {e.msg}")
        
        if e.errno == 2003:
            print("\n   Troubleshooting Hint (Can't connect):")
            print("   1. Ensure Remote MySQL is enabled in Hostinger hPanel.")
            print("   2. Whitelist your IP address in Hostinger 'Remote MySQL' settings.")
            print("   3. Check if your ISP or local firewall blocks port 3306.")
        elif e.errno == 1045:
            print("\n   Troubleshooting Hint (Access denied):")
            print("   1. Double-check your database username and password.")
            print("   2. Ensure the user has permissions for the database.")

if __name__ == "__main__":
    test_connection()
