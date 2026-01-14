import os
import threading
from datetime import timedelta
import docker
from argon2 import PasswordHasher
from flask import Flask, request, redirect, render_template, jsonify, url_for, session, abort
import containerlab_manager as clab
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv
from functools import wraps

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
    is_admin = db.Column(db.Boolean, default=False)


class Lab(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    template = db.Column(db.String(50), nullable=False)
    topology_data = db.Column(db.JSON, nullable=False)
    port_mapping = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', backref=db.backref('labs', lazy=True))


# Helper para métricas
def get_container_stats(container_name):
    """Obtiene métricas de CPU y RAM de un contenedor"""
    try:
        container = client.containers.get(container_name)
        stats = container.stats(stream=False)
        
        # Calcular CPU
        cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - \
                    stats['precpu_stats']['cpu_usage']['total_usage']
        system_delta = stats['cpu_stats']['system_cpu_usage'] - \
                       stats['precpu_stats']['system_cpu_usage']
        
        cpu_percent = 0.0
        if system_delta > 0.0:
            # Multiplicar por número de cores para obtener porcentaje total
            cpu_percent = (cpu_delta / system_delta) * stats['cpu_stats'].get('online_cpus', 1) * 100.0
            
        # Calcular RAM
        mem_usage = stats['memory_stats']['usage']
        mem_limit = stats['memory_stats']['limit']
        mem_percent = (mem_usage / mem_limit) * 100.0
        
        return {
            'cpu': f"{cpu_percent:.1f}%",
            'mem': f"{mem_usage / (1024*1024):.1f}MB ({mem_percent:.1f}%)"
        }
    except Exception:
        return {'cpu': 'N/A', 'mem': 'N/A'}


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
    username = current_user.username

    # Intenta obtener el lab desde la base de datos
    lab_entry = Lab.query.filter_by(user_id=current_user.id).first()
    lab_active = False
    nodes_html = ""

    if lab_entry:
        lab_active = True
        nodes_html = "<div class='nodes'>"
        # Usamos la data guardada en DB en lugar de leer el disco
        topology = lab_entry.topology_data
        for node_name in topology.get('topology', {}).get('nodes', {}).keys():
            url = f"/terminal/{username}/{node_name}"
            nodes_html += f"""
            <div class='node-card'>
                <h3>🖥️ {node_name}</h3>
                <button class='info' onclick='openTerminal("{node_name}", "{url}")'>Abrir Terminal</button>
            </div>
            """
        nodes_html += "</div>"
    else:
        # Fallback de seguridad: verificar si hay algo en containerlab pero no en DB (sincronización básica)
        status = clab.list_labs(username)
        if status.get('success'):
            lab_active = True
            nodes_html = "<div class='section'><p>⚠️ Sincronizando estado...</p></div>"

    return render_template('portal.html', user=username, lab_active=lab_active, nodes_html=nodes_html, ports=lab_entry.port_mapping if lab_entry else {})


@app.route('/api/labs/deploy', methods=['POST'])
@login_required
def api_deploy_lab():
    username = current_user.username
    data = request.get_json()
    template = data.get('template', 'simple-link')

    # 1. Ejecutar despliegue físico
    result = clab.deploy_lab(username, template)

    if result.get('success'):
        try:
            # 2. Guardar estado en BD
            new_lab = Lab(
                user_id=current_user.id,
                name=result['lab_name'],
                template=template,
                topology_data=result['topology'],
                port_mapping=result['ports']
            )
            db.session.add(new_lab)
            db.session.commit()
            return jsonify({'success': True})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': f'Error guardando en BD: {str(e)}'})

    return jsonify(result)


@app.route('/api/labs/destroy', methods=['POST'])
@login_required
def api_destroy_lab():
    username = current_user.username

    # 1. Ejecutar destrucción física
    result = clab.destroy_lab(username)

    if result.get('success'):
        try:
            # 2. Limpiar BD
            Lab.query.filter_by(user_id=current_user.id).delete()
            db.session.commit()
            return jsonify({'success': True})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': f'error limpiando BD: {str(e)}'})

    return jsonify(result)
# --- Admin Routes ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()
    labs = Lab.query.all()
    # Enviamos labs básicos, la info de nodos se cargará vía JS
    return render_template('admin.html', users=users, labs=labs)


@app.route('/api/admin/labs/<int:lab_id>/status')
@login_required
@admin_required
def api_admin_lab_status(lab_id):
    lab = Lab.query.get_or_404(lab_id)
    user = User.query.get(lab.user_id)
    
    if not user:
        return jsonify({'success': False, 'error': 'Usuario no encontrado'})
    
    nodes_info = []
    clab_status = clab.list_labs(user.username)
    
    if clab_status.get('success'):
        data = clab_status['data']
        for node_name, node_data in data['nodes'].items():
            stats = get_container_stats(node_data['container_name'])
            nodes_info.append({
                'name': node_name,
                'ipv4': node_data['ipv4'],
                'cpu': stats['cpu'],
                'mem': stats['mem']
            })
    
    return jsonify({
        'success': True,
        'nodes': nodes_info
    })


@app.route('/api/admin/labs/destroy/<int:lab_id>', methods=['POST'])
@login_required
@admin_required
def api_admin_destroy_lab(lab_id):
    lab = Lab.query.get_or_404(lab_id)
    # 1. Obtener el usuario del lab para clab
    user = User.query.get(lab.user_id)
    if not user:
        return jsonify({'success': False, 'error': 'Usuario no encontrado'})

    # 2. Destrucción física
    result = clab.destroy_lab(user.username)
    if result.get('success'):
        db.session.delete(lab)
        db.session.commit()
    return jsonify(result)


@app.route('/api/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def api_admin_delete_user(user_id):
    if user_id == current_user.id:
        return jsonify({'success': False, 'error': 'No puedes borrarte a ti mismo'})

    user = User.query.get_or_404(user_id)

    # 1. Destruir lab si existe
    lab = Lab.query.filter_by(user_id=user.id).first()
    if lab:
        clab.destroy_lab(user.username)
        db.session.delete(lab)

    # 2. Borrar usuario
    db.session.delete(user)
    db.session.commit()
    return jsonify({'success': True})


# --- Socket.IO y Terminal ---
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
