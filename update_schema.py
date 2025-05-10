import sqlite3

conn = sqlite3.connect('users.db')
c = conn.cursor()

try:
    c.execute("ALTER TABLE withdrawals ADD COLUMN fee REAL;")
    print("Column 'fee' added successfully.")
except Exception as e:
    print("Error:", e)

conn.commit()
conn.close()
