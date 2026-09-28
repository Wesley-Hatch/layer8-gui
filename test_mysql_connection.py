import pymysql
import os
import socket

def test_connection():
    # Database connection details
    DB_HOST = os.getenv('L8_DB_HOST')
    DB_USER = os.getenv('MYSQL_USER') or os.getenv('DB_USER')
    DB_PASSWORD = os.getenv('MYSQL_PASSWORD') or os.getenv('DB_PASS')
    DB_NAME = os.getenv('L8_DB_NAME')
    DB_PORT = os.getenv('L8_DB_PORT', '3306')

    print("--- MySQL Connection Diagnostic (using PyMySQL) ---")
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
        conn = pymysql.connect(
            host=DB_HOST,
            port=int(DB_PORT),
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            connect_timeout=5,
            autocommit=True
        )
        print("Connection object created. Checking if connected...")

        if conn.open:
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
            print("❌ MySQL Connection: FAILED (open returned False)")
    except pymysql.Error as e:
        print(f"❌ MySQL Connection: FAILED")
        errno = e.args[0] if e.args else 0
        msg = e.args[1] if len(e.args) > 1 else str(e)
        print(f"   Error Code: {errno}")
        print(f"   Message: {msg}")
        
        if errno == 2003:
            print("\n   Troubleshooting Hint (Can't connect):")
            print("   1. Ensure Remote MySQL is enabled in Hostinger hPanel.")
            print("   2. Whitelist your IP address in Hostinger 'Remote MySQL' settings.")
            print("   3. Check if your ISP or local firewall blocks port 3306.")
        elif errno == 1045:
            print("\n   Troubleshooting Hint (Access denied):")
            print("   1. Double-check your database username and password.")
            print("   2. Ensure the user has permissions for the database.")

if __name__ == "__main__":
    test_connection()
