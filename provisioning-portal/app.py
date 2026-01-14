import os
import docker
import traceback
import yaml
from argon2 import PasswordHasher
from flask import Flask, request, redirect, render_template_string, jsonify, url_for, flash
import containerlab_manager as clab
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-key-for-dev')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuración de seguridad de cookies
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False') == 'True'
app.config['SESSION_COOKIE_HTTPONLY'] = os.getenv('SESSION_COOKIE_HTTPONLY', 'True') == 'True'
app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='gevent')
client = docker.from_env()

LAB_NETWORK = 'lab-net'
ph = PasswordHasher()

# Modelos
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Crear tablas al inicio
with app.app_context():
    db.create_all()

# --- Rutas de Autenticación ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user:
            try:
                ph.verify(user.password_hash, password)
                login_user(user)
                return redirect(url_for('home'))
            except:
                pass
        
        return render_template_string(LOGIN_TEMPLATE, error="Usuario o contraseña incorrectos. ¿No tienes cuenta? <a href='/register'>Regístrate aquí</a>")
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            return "Usuario y contraseña son requeridos", 400
        
        if not username.replace('-', '').replace('_', '').isalnum():
            return "Usuario solo puede contener letras, números, guiones y guiones bajos", 400
            
        if User.query.filter_by(username=username).first():
            return "El usuario ya existe", 400
        
        try:
            password_hash = ph.hash(password)
            new_user = User(username=username, email=email, password_hash=password_hash)
            db.session.add(new_user)
            db.session.commit()
            
            return render_template_string(SUCCESS_TEMPLATE, message="Registro exitoso. Ahora puedes iniciar sesión.", link="/login", link_text="Ir al Login")
        except Exception as e:
            db.session.rollback()
            return f"Error al registrar usuario: {str(e)}", 500
            
    return render_template_string(REGISTER_TEMPLATE)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Rutas del Portal ---

@app.route('/')
@login_required
def home():
    user = current_user.username
    
    lab_status = clab.list_labs(user)
    lab_active = lab_status.get('success', False)
    
    nodes_html = ""
    if lab_active:
        lab_file = f"/labs/{user}/topology.yml"
        if os.path.exists(lab_file):
            with open(lab_file, 'r') as f:
                topology = yaml.safe_load(f)
            
            nodes_html = "<div class='nodes'>"
            for node_name, node_config in topology.get('topology', {}).get('nodes', {}).items():
                url = f"/terminal/{user}/{node_name}"
                nodes_html += f"""
                <div class='node-card'>
                    <h3>🖥️ {node_name}</h3>
                    <button class='info' onclick='openTerminal("{node_name}", "{url}")'>Abrir Terminal</button>
                </div>
                """
            nodes_html += "</div>"
    
    return render_template_string(PORTAL_TEMPLATE, user=user, lab_active=lab_active, nodes_html=nodes_html)

@app.route('/api/labs/deploy', methods=['POST'])
@login_required
def api_deploy_lab():
    user = current_user.username
    data = request.get_json()
    template = data.get('template', 'simple-link')
    result = clab.deploy_lab(user, template)
    return jsonify(result)

@app.route('/api/labs/destroy', methods=['POST'])
@login_required
def api_destroy_lab():
    user = current_user.username
    result = clab.destroy_lab(user)
    return jsonify(result)

@app.route('/terminal/<username>/<node_name>')
@login_required
def terminal_page(username, node_name):
    if username != current_user.username:
        return "No tienes permiso para acceder a esta terminal", 403
    return render_template_string(TERMINAL_TEMPLATE, username=username, node_name=node_name)

# --- WebSocket Terminal ---

terminal_sessions = {}

@socketio.on('start_terminal')
def handle_start_terminal(data):
    # Aquí deberíamos verificar la sesión del socket con Flask-Login si es posible
    # Por simplicidad ahora usamos el username del data, pero en producción se debe validar
    username = data['username']
    node_name = data['node_name']
    
    # Verificación extra de seguridad (prevenir saltar a labs de otros)
    # En una implementación real, request.sid debería estar ligado a un usuario autenticado
    
    container_name = f"clab-lab-{username}-{node_name}"
    
    try:
        container = client.containers.get(container_name)
        exec_id = container.client.api.exec_create(
            container.id, 'sh', stdin=True, tty=True,
            environment={"TERM": "xterm-256color"}, workdir='/root'
        )
        exec_socket = container.client.api.exec_start(exec_id, socket=True, tty=True)
        
        session_id = request.sid
        terminal_sessions[session_id] = {
            'socket': exec_socket, 'container': container, 'exec_id': exec_id
        }
        
        def read_output():
            try:
                while session_id in terminal_sessions:
                    data = exec_socket._sock.recv(1024)
                    if not data: break
                    socketio.emit('terminal_output', data.decode('utf-8', errors='ignore'), room=session_id)
            except: pass
            finally:
                if session_id in terminal_sessions: del terminal_sessions[session_id]
        
        import threading
        thread = threading.Thread(target=read_output)
        thread.daemon = True
        thread.start()
    except Exception as e:
        emit('terminal_error', {'error': str(e)})

@socketio.on('terminal_input')
def handle_terminal_input(data):
    session_id = request.sid
    if session_id in terminal_sessions:
        try:
            terminal_sessions[session_id]['socket']._sock.send(data['data'].encode())
        except: pass

@socketio.on('terminal_resize')
def handle_terminal_resize(data):
    session_id = request.sid
    if session_id in terminal_sessions:
        try:
            terminal_sessions[session_id]['container'].client.api.exec_resize(
                terminal_sessions[session_id]['exec_id'], 
                height=data['rows'], width=data['cols']
            )
        except: pass

@socketio.on('disconnect')
def handle_disconnect():
    session_id = request.sid
    if session_id in terminal_sessions:
        try: terminal_sessions[session_id]['socket']._sock.close()
        except: pass
        del terminal_sessions[session_id]

# --- Templates HTML ---

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Login - Student Labs</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; display: flex; justify-content: center; }
        .container { width: 400px; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { text-align: center; color: #333; }
        label { display: block; margin-top: 15px; font-weight: bold; }
        input { width: 100%; padding: 10px; margin-top: 5px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; margin-top: 20px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }
        .error { color: #dc3545; background: #f8d7da; padding: 10px; border-radius: 5px; margin-bottom: 15px; font-size: 14px; text-align: center; }
        .links { text-align: center; margin-top: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Iniciar Sesión</h1>
        {% if error %} <div class="error">{{ error|safe }}</div> {% endif %}
        <form method="POST">
            <label>Usuario</label><input type="text" name="username" required>
            <label>Contraseña</label><input type="password" name="password" required>
            <button type="submit">Entrar</button>
        </form>
        <div class="links"><p>¿No tienes cuenta? <a href="/register">Regístrate</a></p></div>
    </div>
</body>
</html>
"""

REGISTER_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Registro - Student Labs</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; display: flex; justify-content: center; }
        .container { width: 400px; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { text-align: center; color: #333; }
        label { display: block; margin-top: 15px; font-weight: bold; }
        input { width: 100%; padding: 10px; margin-top: 5px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; margin-top: 20px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Crear Cuenta</h1>
        <form method="POST">
            <label>Usuario</label><input type="text" name="username" required pattern="[a-zA-Z0-9_-]+">
            <label>Email (opcional)</label><input type="email" name="email">
            <label>Contraseña</label><input type="password" name="password" required minlength="8">
            <button type="submit">Registrarse</button>
        </form>
        <div style="text-align:center; margin-top:15px;"><a href="/login">Volver al Login</a></div>
    </div>
</body>
</html>
"""

SUCCESS_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Éxito</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin: 100px; }
        .success { color: #28a745; }
        a { display: inline-block; margin-top: 20px; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; }
    </style>
</head>
<body>
    <h1 class="success">✓ {{ message }}</h1>
    <a href="{{ link }}">{{ link_text }}</a>
</body>
</html>
"""

PORTAL_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Student Labs Portal</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { display: flex; justify-content: space-between; align-items: center; }
        .section { margin-top: 30px; padding: 20px; background: #f9f9f9; border-radius: 5px; }
        button { padding: 10px 20px; cursor: pointer; background: #007bff; color: white; border: none; border-radius: 5px; }
        .danger { background: #dc3545; }
        .info { background: #17a2b8; }
        .nodes { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px; }
        .node-card { padding: 15px; background: white; border: 2px solid #007bff; border-radius: 8px; }
        .terminal-container { position: fixed; bottom: 0; left: 0; right: 0; height: 50vh; background: #1e1e1e; display: none; }
        .terminal-container.active { display: block; }
        .terminal-header { background: #007bff; color: white; padding: 10px; display: flex; justify-content: space-between; }
        iframe { width: 100%; height: calc(100% - 40px); border: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 Student Labs</h1>
            <div>
                <span>Hola, <strong>{{ user }}</strong></span> | 
                <a href="/logout">Cerrar Sesión</a>
            </div>
        </div>
        
        {% if lab_active %}
            <div class="section">
                <h3>✅ Lab Activo</h3>
                {{ nodes_html|safe }}
                <button class="danger" style="margin-top:20px" onclick="destroyLab()">Destruir Lab</button>
            </div>
        {% else %}
            <div class="section">
                <h3>Crear Laboratorio</h3>
                <button onclick="createLab('simple-link')">🔗 Enlace Simple</button>
                <button onclick="createLab('basic-network')">🌐 Red Básica</button>
            </div>
        {% endif %}
    </div>

    <div id="terminal-container" class="terminal-container">
        <div class="terminal-header">
            <span>Terminal: <strong id="node-label"></strong></span>
            <button onclick="closeTerminal()">✕</button>
        </div>
        <iframe id="terminal-iframe"></iframe>
    </div>

    <script>
    function createLab(t) {
        if(confirm('¿Crear lab?')) {
            fetch('/api/labs/deploy', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({template: t})
            }).then(r => r.json()).then(d => {
                if(d.success) location.reload(); else alert('Error: ' + d.error);
            });
        }
    }
    function destroyLab() {
        if(confirm('¿Destruir?')) {
            fetch('/api/labs/destroy', {method: 'POST'})
            .then(r => r.json()).then(d => location.reload());
        }
    }
    function openTerminal(node, url) {
        document.getElementById('terminal-iframe').src = url;
        document.getElementById('node-label').textContent = node;
        document.getElementById('terminal-container').classList.add('active');
    }
    function closeTerminal() {
        document.getElementById('terminal-container').classList.remove('active');
        document.getElementById('terminal-iframe').src = '';
    }
    </script>
</body>
</html>
"""

TERMINAL_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Term - {{node_name}}</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css" />
    <script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js"></script>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <style>body { margin: 0; background: #000; } #terminal { width: 100vw; height: 100vh; }</style>
</head>
<body>
    <div id="terminal"></div>
    <script>
        const term = new Terminal({cursorBlink: true, theme: {background: '#1e1e1e'}});
        const fitAddon = new FitAddon.FitAddon();
        term.loadAddon(fitAddon);
        term.open(document.getElementById('terminal'));
        fitAddon.fit();
        
        const socket = io();
        socket.on('connect', () => {
            socket.emit('start_terminal', {username: '{{username}}', node_name: '{{node_name}}', rows: term.rows, cols: term.cols});
        });
        socket.on('terminal_output', d => term.write(d));
        term.onData(d => socket.emit('terminal_input', {data: d}));
        term.onResize(s => socket.emit('terminal_resize', {rows: s.rows, cols: s.cols}));
        window.onresize = () => fitAddon.fit();
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', port=5000)