from flask import Flask, request, render_template_string, make_response
import sqlite3

app = Flask(__name__)
app.secret_key = "weak"
        
@app.route("/")
def index():
    resp = make_response("""
    <h1>Vulnerable Demo</h1>
    <a href="/search?q=test">Search</a><br>
    <a href="/login">Login</a><br>
    <a href="/user?id=1">User</a>
    """)
    resp.set_cookie("session", "abc123", httponly=True, samesite='Lax')
    return resp

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return render_template_string(f"<h2>Results for {q}</h2>")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        resp = make_response("Logged in")
        resp.set_cookie("session", "abc123", httponly=True, samesite='Lax')
        return resp
    return """
    <form method="post">
    Username: <input name="username"><br>
    Password: <input name="password" type="password"><br>
    <button type="submit">Login</button>
    </form>
    """

@app.route("/user")
def user():
    uid = request.args.get("id", "1")
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    cur.execute("INSERT INTO users VALUES (1, 'Alice')")
    query = f"SELECT name FROM users WHERE id = {uid}"
    try:
        cur.execute(query)
        row = cur.fetchone()
        return f"User: {row[0] if row else 'not found'}"
    except Exception as e:
        return f"SQL error: {e}", 500

@app.route("/.env")
def env_file():
    return "SECRET_KEY=supersecret\nDB_PASSWORD=password123"

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
