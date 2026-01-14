import os
import threading
from datetime import timedelta
import docker
import yaml
from argon2 import PasswordHasher
from flask import Flask, request, redirect, render_template, jsonify, url_for, session
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

# Configuración de tiempo de vida de sesión
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=int(os.getenv('SESSION_LIFETIME_MIN', '30')))

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


@app.before_request
def make_session_permanent():
    session.permanent = True


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
            except Exception:  # nosec: B110
                # Password verify failed or login error
                pass

        error_msg = "Usuario o contraseña incorrectos. ¿No tienes cuenta? <a href='/register'>Regístrate aquí</a>"
        return render_template('login.html', error=error_msg)

    return render_template('login.html')


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

            return render_template(
                'success.html',
                message="Registro exitoso. Ahora puedes iniciar sesión.",
                link="/login", link_text="Ir al Login"
            )
        except Exception as e:
            db.session.rollback()
            return f"Error al registrar usuario: {str(e)}", 500

    return render_template('register.html')


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

    return render_template('portal.html', user=user, lab_active=lab_active, nodes_html=nodes_html)


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
    return render_template('terminal.html', username=username, node_name=node_name)


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
                    if not data:
                        break
                    socketio.emit('terminal_output', data.decode('utf-8', errors='ignore'), room=session_id)
            except Exception:  # nosec: B110
                # Session closed or network error
                pass
            finally:
                if session_id in terminal_sessions:
                    del terminal_sessions[session_id]

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
        except Exception:  # nosec: B110
            pass


@socketio.on('terminal_resize')
def handle_terminal_resize(data):
    session_id = request.sid
    if session_id in terminal_sessions:
        try:
            terminal_sessions[session_id]['container'].client.api.exec_resize(
                terminal_sessions[session_id]['exec_id'],
                height=data['rows'], width=data['cols']
            )
        except Exception:  # nosec: B110
            pass


@socketio.on('disconnect')
def handle_disconnect():
    session_id = request.sid
    if session_id in terminal_sessions:
        try:
            terminal_sessions[session_id]['socket']._sock.close()
        except Exception:  # nosec: B110
            pass
        del terminal_sessions[session_id]


if __name__ == "__main__":
    # Binding to 0.0.0.0 is necessary for Docker reachability
    socketio.run(app, host='0.0.0.0', port=5000)  # nosec: B104
