import sqlite3

# connect ke database
conn = sqlite3.connect("user.db")
cursor = conn.cursor()

#check table users wujud ke tak
cursor.execute("SELECT name FROM sqlite_master WHERE type= 'table';")
print("Tables:", cursor.fetchall())

#check columns dalam table users 
cursor.execute("PRAGMA table_info(users);")
print("Columns:",cursor.fetchall())

conn.close()