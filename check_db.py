import sqlite3
from tabulate import tabulate

def inspect_database(db_path="user.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # ambil semua nama table
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [t[0] for t in cursor.fetchall()]

    print("Senarai table dalam database:")
    for table in tables:
        print(f"- {table}")

    print("\nDetail setiap table:\n")

    # loop semua table
    for table in tables:
        print(f"Table: {table}")

        # ambil column info
        cursor.execute(f"PRAGMA table_info({table});")
        columns = cursor.fetchall()
        col_names = [col[1] for col in columns]
        print("Columns:", col_names)

        # ambil semua data
        cursor.execute(f"SELECT * FROM {table};")
        rows = cursor.fetchall()
        print("Data:")
        if rows:
            print(tabulate(rows, headers=col_names, tablefmt="grid"))
        else:
            print("  (tiada data)")

        print("-" * 60)

    conn.close()


if __name__ == "__main__":
    inspect_database()
