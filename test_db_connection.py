from db_connection import DatabaseConnection

print("Starting Database Connection Test...")
db = DatabaseConnection()
success, msg = db.test_connection()
print(f"Result: {msg}")

if success:
    print("✅ Success! Your Python backend is now synced with the PHP encryption.")
else:
    print("❌ Failure! Check database_connection.log for more details.")
