# app.py
# High-quality, single-file Flask Task Manager with Authentication and SQLite
# 100% English. All code in one block — ready to copy-paste into app.py and run.
#
# Features:
# - User registration and login (passwords hashed)
# - Session-based auth
# - Create / Edit / Delete / Toggle tasks
# - Task due date and priority
# - SQLite persistence (single file)
# - Responsive UI with Bootstrap (CDN)
# - Simple input validation and flash messages
#
# Requirements:
# pip install flask werkzeug
#
# Run:
# python app.py
# Visit http://localhost:5000

import os
import sqlite3
from datetime import datetime
from functools import wraps
from flask import (
    Flask, request, redirect, url_for, render_template_string,
    session, flash, g
)
from werkzeug.security import generate_password_hash, check_password_hash

APP_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(APP_DIR, "task_manager.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key")  # change in production
app.config["DATABASE"] = DB_PATH

# ---------------------------
# Database helpers
# ---------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

app.teardown_appcontext(close_db)

def init_db():
    db = get_db()
    # users table and tasks table
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        details TEXT,
        priority INTEGER DEFAULT 2, -- 1 = high, 2 = normal, 3 = low
        due_date TEXT,
        completed INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    db.commit()

# Initialize DB on first run
with app.app_context():
    init_db()

# ---------------------------
# Auth helpers
# ---------------------------
def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped_view

def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    db = get_db()
    user = db.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
    return user

# ---------------------------
# Routes: auth
# ---------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password are required.", "danger")
        else:
            db = get_db()
            existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if existing:
                flash("Username already taken. Please choose another.", "warning")
            else:
                pw_hash = generate_password_hash(password)
                created = datetime.utcnow().isoformat()
                db.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                           (username, pw_hash, created))
                db.commit()
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for("login"))
    return render_template_string(BASE_TEMPLATE, content=render_template_string(REGISTER_TEMPLATE))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            flash("Logged in successfully.", "success")
            next_url = request.args.get("next") or url_for("index")
            return redirect(next_url)
        else:
            flash("Invalid username or password.", "danger")
    return render_template_string(BASE_TEMPLATE, content=render_template_string(LOGIN_TEMPLATE))

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))

# ---------------------------
# Routes: tasks
# ---------------------------
@app.route("/")
@login_required
def index():
    user = get_current_user()
    db = get_db()
    tasks = db.execute("""
        SELECT * FROM tasks WHERE user_id = ? ORDER BY completed ASC, priority ASC, due_date IS NULL, due_date ASC, created_at DESC
    """, (user["id"],)).fetchall()
    return render_template_string(BASE_TEMPLATE, content=render_template_string(INDEX_TEMPLATE, user=user, tasks=tasks))

@app.route("/task/add", methods=["POST"])
@login_required
def add_task():
    title = request.form.get("title", "").strip()
    details = request.form.get("details", "").strip()
    priority = int(request.form.get("priority", 2))
    due_date = request.form.get("due_date") or None
    if not title:
        flash("Task title cannot be empty.", "danger")
        return redirect(url_for("index"))
    db = get_db()
    db.execute("""
        INSERT INTO tasks (user_id, title, details, priority, due_date, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (session["user_id"], title, details, priority, due_date, datetime.utcnow().isoformat()))
    db.commit()
    flash("Task added.", "success")
    return redirect(url_for("index"))

@app.route("/task/<int:task_id>/toggle")
@login_required
def toggle_task(task_id):
    db = get_db()
    task = db.execute("SELECT * FROM tasks WHERE id = ? AND user_id = ?", (task_id, session["user_id"])).fetchone()
    if task:
        db.execute("UPDATE tasks SET completed = ? WHERE id = ?", (0 if task["completed"] else 1, task_id))
        db.commit()
        flash("Task updated.", "success")
    else:
        flash("Task not found.", "warning")
    return redirect(url_for("index"))

@app.route("/task/<int:task_id>/delete", methods=["POST"])
@login_required
def delete_task(task_id):
    db = get_db()
    db.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", (task_id, session["user_id"]))
    db.commit()
    flash("Task deleted.", "info")
    return redirect(url_for("index"))

@app.route("/task/<int:task_id>/edit", methods=["GET", "POST"])
@login_required
def edit_task(task_id):
    db = get_db()
    task = db.execute("SELECT * FROM tasks WHERE id = ? AND user_id = ?", (task_id, session["user_id"])).fetchone()
    if not task:
        flash("Task not found.", "warning")
        return redirect(url_for("index"))
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        details = request.form.get("details", "").strip()
        priority = int(request.form.get("priority", 2))
        due_date = request.form.get("due_date") or None
        if not title:
            flash("Title cannot be empty.", "danger")
            return redirect(url_for("edit_task", task_id=task_id))
        db.execute("""
            UPDATE tasks SET title=?, details=?, priority=?, due_date=? WHERE id=? AND user_id=?
        """, (title, details, priority, due_date, task_id, session["user_id"]))
        db.commit()
        flash("Task saved.", "success")
        return redirect(url_for("index"))
    return render_template_string(BASE_TEMPLATE, content=render_template_string(EDIT_TEMPLATE, task=task))

# ---------------------------
# Templates (single-file approach)
# ---------------------------

BASE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Task Manager Pro</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { background: #f4f7fb; }
    .task-high { border-left: 5px solid #dc3545; }
    .task-normal { border-left: 5px solid #ffc107; }
    .task-low { border-left: 5px solid #198754; }
    .small-muted { font-size: .85rem; color: #6c757d; }
    .container { padding-top: 30px; padding-bottom: 60px; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('index') }}">TaskManager Pro</a>
    <div class="collapse navbar-collapse">
      <ul class="navbar-nav ms-auto">
        {% if session.user_id %}
        <li class="nav-item"><a class="nav-link" href="{{ url_for('index') }}">Dashboard</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">Logout</a></li>
        {% else %}
        <li class="nav-item"><a class="nav-link" href="{{ url_for('login') }}">Login</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('register') }}">Register</a></li>
        {% endif %}
      </ul>
    </div>
  </div>
</nav>

<div class="container">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
          {{ message }}
          <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
      {% endfor %}
    {% endif %}
  {% endwith %}

  {{ content|safe }}
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

REGISTER_TEMPLATE = """
<div class="row justify-content-center">
  <div class="col-md-6">
    <div class="card shadow-sm">
      <div class="card-body">
        <h4 class="card-title mb-3">Register</h4>
        <form method="POST">
          <div class="mb-3">
            <label class="form-label">Username</label>
            <input class="form-control" name="username" required>
          </div>
          <div class="mb-3">
            <label class="form-label">Password</label>
            <input class="form-control" name="password" type="password" required>
          </div>
          <button class="btn btn-primary w-100">Create account</button>
        </form>
        <div class="small-muted mt-3">Already have an account? <a href="{{ url_for('login') }}">Login</a></div>
      </div>
    </div>
  </div>
</div>
"""

LOGIN_TEMPLATE = """
<div class="row justify-content-center">
  <div class="col-md-6">
    <div class="card shadow-sm">
      <div class="card-body">
        <h4 class="card-title mb-3">Login</h4>
        <form method="POST">
          <div class="mb-3">
            <label class="form-label">Username</label>
            <input class="form-control" name="username" required>
          </div>
          <div class="mb-3">
            <label class="form-label">Password</label>
            <input class="form-control" name="password" type="password" required>
          </div>
          <button class="btn btn-primary w-100">Sign in</button>
        </form>
        <div class="small-muted mt-3">New here? <a href="{{ url_for('register') }}">Create an account</a></div>
      </div>
    </div>
  </div>
</div>
"""

INDEX_TEMPLATE = """
<div class="row">
  <div class="col-md-8">
    <div class="card mb-4 shadow-sm">
      <div class="card-body">
        <h4 class="card-title">Hello, {{ user.username }}!</h4>
        <p class="small-muted">Manage your tasks efficiently. Add a new task below.</p>

        <form method="POST" action="{{ url_for('add_task') }}" class="row g-2 align-items-end">
          <div class="col-md-6">
            <label class="form-label">Title</label>
            <input name="title" class="form-control" placeholder="Task title" required>
          </div>
          <div class="col-md-6">
            <label class="form-label">Priority</label>
            <select name="priority" class="form-select">
              <option value="1">High</option>
              <option value="2" selected>Normal</option>
              <option value="3">Low</option>
            </select>
          </div>
          <div class="col-md-12">
            <label class="form-label">Details (optional)</label>
            <textarea name="details" class="form-control" rows="2" placeholder="Details..."></textarea>
          </div>
          <div class="col-md-6">
            <label class="form-label">Due date (optional)</label>
            <input name="due_date" type="date" class="form-control">
          </div>
          <div class="col-md-6 text-end">
            <button class="btn btn-success">Add Task</button>
          </div>
        </form>
      </div>
    </div>

    {% for t in tasks %}
      {% set cls = 'task-normal' %}
      {% if t.priority == 1 %}{% set cls = 'task-high' %}{% endif %}
      {% if t.priority == 3 %}{% set cls = 'task-low' %}{% endif %}

      <div class="card mb-2 shadow-sm {{ cls }}">
        <div class="card-body d-flex justify-content-between align-items-start">
          <div>
            <h5 class="{% if t.completed %}text-decoration-line-through{% endif %}">{{ t.title }}</h5>
            <div class="small-muted">{{ t.details }}</div>
            <div class="small-muted mt-2">
              Created: {{ t.created_at.split('T')[0] }}
              {% if t.due_date %} • Due: {{ t.due_date }}{% endif %}
            </div>
          </div>
          <div class="text-end">
            <a href="{{ url_for('toggle_task', task_id=t.id) }}" class="btn btn-outline-primary btn-sm mb-2">
              {% if t.completed %}Mark Active{% else %}Mark Done{% endif %}
            </a>
            <a href="{{ url_for('edit_task', task_id=t.id) }}" class="btn btn-outline-secondary btn-sm mb-2">Edit</a>
            <form method="POST" action="{{ url_for('delete_task', task_id=t.id) }}" style="display:inline">
              <button class="btn btn-outline-danger btn-sm" type="submit">Delete</button>
            </form>
          </div>
        </div>
      </div>
    {% else %}
      <div class="card mb-2 shadow-sm">
        <div class="card-body">
          <p class="small-muted mb-0">No tasks yet. Add your first task above.</p>
        </div>
      </div>
    {% endfor %}
  </div>

  <div class="col-md-4">
    <div class="card mb-3 shadow-sm">
      <div class="card-body">
        <h5>Summary</h5>
        {% set total = tasks|length %}
        {% set done = tasks|selectattr("completed")|list|length %}
        <p class="small-muted">Total: {{ total }} • Completed: {{ done }}</p>
      </div>
    </div>

    <div class="card shadow-sm">
      <div class="card-body">
        <h5>Tips</h5>
        <ul class="small-muted">
          <li>Use priorities to focus on important tasks.</li>
          <li>Set due dates to stay on schedule.</li>
          <li>Keep task details short and actionable.</li>
        </ul>
      </div>
    </div>
  </div>
</div>
"""

EDIT_TEMPLATE = """
<div class="row justify-content-center">
  <div class="col-md-8">
    <div class="card shadow-sm">
      <div class="card-body">
        <h4 class="card-title mb-3">Edit Task</h4>
        <form method="POST">
          <div class="mb-3">
            <label class="form-label">Title</label>
            <input class="form-control" name="title" value="{{ task.title }}" required>
          </div>
          <div class="mb-3">
            <label class="form-label">Details</label>
            <textarea name="details" class="form-control">{{ task.details }}</textarea>
          </div>
          <div class="mb-3">
            <label class="form-label">Priority</label>
            <select name="priority" class="form-select">
              <option value="1" {% if task.priority==1 %}selected{% endif %}>High</option>
              <option value="2" {% if task.priority==2 %}selected{% endif %}>Normal</option>
              <option value="3" {% if task.priority==3 %}selected{% endif %}>Low</option>
            </select>
          </div>
          <div class="mb-3">
            <label class="form-label">Due date</label>
            <input name="due_date" type="date" class="form-control" value="{{ task.due_date }}">
          </div>
          <button class="btn btn-primary">Save</button>
          <a class="btn btn-link" href="{{ url_for('index') }}">Cancel</a>
        </form>
      </div>
    </div>
  </div>
</div>
"""

# ---------------------------
# Run app
# ---------------------------
if __name__ == "__main__":
    app.run(debug=True)
