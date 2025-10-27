import sqlite3

def vulnerable_query(user_input):
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    # Vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE username = '{user_input}' AND password = 'secret'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results

# Example usage with injection
if __name__ == "__main__":
    user_input = "admin' --"
    print(vulnerable_query(user_input))
