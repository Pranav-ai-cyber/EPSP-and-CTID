import sqlite3

def vulnerable_query(user_input):
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    # Vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results

# Example usage
if __name__ == "__main__":
    user_input = "admin' OR '1'='1"
    print(vulnerable_query(user_input))
