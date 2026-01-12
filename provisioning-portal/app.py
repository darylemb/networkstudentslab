import os
import docker
import traceback
import yaml
from argon2 import PasswordHasher
from flask import Flask, request, redirect, render_template_string, jsonify
import containerlab_manager as clab
from flask_socketio import SocketIO, emit
import pty
import subprocess
import select
import struct
import fcntl
import termios

app = Flask(__name__)
app.config['SECRET_KEY'] = 'student-labs-secret-2026'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='gevent')
client = docker.from_env()

LAB_NETWORK = 'lab-net'

# Ruta de registro público (sin autenticación)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            return "Usuario y contraseña son requeridos", 400
        
        # Validar formato de usuario (solo letras, números, guiones)
        if not username.replace('-', '').replace('_', '').isalnum():
            return "Usuario solo puede contener letras, números, guiones y guiones bajos", 400
        
        try:
            # Generar hash de contraseña con argon2id (compatible con Authelia)
            ph = PasswordHasher()
            password_hash = ph.hash(password)
            
            # Leer archivo users.yml de Authelia
            users_file = '/authelia-config/users.yml'
            with open(users_file, 'r') as f:
                users_data = yaml.safe_load(f) or {'users': {}}
            
            # Verificar si el usuario ya existe
            if username in users_data.get('users', {}):
                return "El usuario ya existe", 400
            
            # Agregar nuevo usuario
            if 'users' not in users_data:
                users_data['users'] = {}
            
            users_data['users'][username] = {
                'disabled': False,
                'displayname': username.capitalize(),
                'password': password_hash,
                'email': email if email else f"{username}@localhost",
                'groups': ['students']
            }
            
            # Guardar archivo actualizado
            with open(users_file, 'w') as f:
                yaml.dump(users_data, f, default_flow_style=False)
            
            return """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Registro Exitoso</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
                    .success { color: green; }
                    a { display: inline-block; margin-top: 20px; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; }
                </style>
            </head>
            <body>
                <h1 class="success">✓ Registro Exitoso</h1>
                <p>Tu cuenta ha sido creada. Ahora puedes iniciar sesión.</p>
                <a href="/">Ir al Portal</a>
            </body>
            </html>
            """
        except Exception as e:
            print(f"Error en registro: {str(e)}")
            traceback.print_exc()
            return f"Error al registrar usuario: {str(e)}", 500
    
    # GET: Mostrar formulario de registro
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Registro - Student Labs</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #333; text-align: center; }
            label { display: block; margin-top: 15px; font-weight: bold; }
            input { width: 100%; padding: 10px; margin-top: 5px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
            button { width: 100%; padding: 12px; margin-top: 20px; background: #007bff; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; }
            button:hover { background: #0056b3; }
            .login-link { text-align: center; margin-top: 15px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Crear Cuenta</h1>
            <form method="POST">
                <label for="username">Usuario:</label>
                <input type="text" id="username" name="username" required pattern="[a-zA-Z0-9_-]+" title="Solo letras, números, guiones y guiones bajos">
                
                <label for="email">Email (opcional):</label>
                <input type="email" id="email" name="email">
                
                <label for="password">Contraseña:</label>
                <input type="password" id="password" name="password" required minlength="8">
                
                <button type="submit">Registrarse</button>
            </form>
            <div class="login-link">
                <p>¿Ya tienes cuenta? <a href="/">Iniciar sesión</a></p>
            </div>
        </div>
    </body>
    </html>
    """

# Ruta principal del portal
@app.route('/')
def home():
    user = request.headers.get('Remote-User', 'invitado')
    
    # Verificar si el usuario ya tiene un lab activo
    lab_status = clab.list_labs(user)
    lab_active = lab_status.get('success', False)
    
    # Si hay lab activo, mostrar nodos
    nodes_html = ""
    if lab_active:
        import glob
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
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Student Labs Portal - ContainerLab</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
            .container {{ max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            h1 {{ color: #333; }}
            .section {{ margin-top: 30px; padding: 20px; background: #f9f9f9; border-radius: 5px; }}
            button {{ padding: 12px 24px; margin: 5px; font-size: 14px; cursor: pointer; background: #007bff; color: white; border: none; border-radius: 5px; }}
            button:hover {{ background: #0056b3; }}
            .danger {{ background: #dc3545; }}
            .danger:hover {{ background: #c82333; }}
            .info {{ background: #17a2b8; padding: 8px 16px; font-size: 12px; }}
            .info:hover {{ background: #138496; }}
            .success {{ background: #28a745; }}
            .nodes {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-top: 15px; }}
            .node-card {{ padding: 20px; background: white; border-radius: 8px; border: 2px solid #007bff; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
            .node-card h3 {{ margin: 0 0 10px 0; color: #007bff; font-size: 18px; }}
            .node-card p {{ margin: 5px 0; color: #666; }}
            .node-card a {{ text-decoration: none; }}
            .status {{ padding: 10px; background: #d4edda; border: 1px solid #c3e6cb; border-radius: 5px; color: #155724; margin-bottom: 15px; }}
            
            /* Terminal embebido */
            .terminal-container {{ position: fixed; bottom: 0; left: 0; right: 0; height: 50vh; background: #1e1e1e; border-top: 3px solid #007bff; display: none; z-index: 1000; }}
            .terminal-container.active {{ display: block; }}
            .terminal-header {{ background: #007bff; color: white; padding: 10px 15px; display: flex; justify-content: space-between; align-items: center; }}
            .terminal-header h4 {{ margin: 0; }}
            .terminal-close {{ background: #dc3545; border: none; color: white; padding: 5px 15px; cursor: pointer; border-radius: 3px; }}
            .terminal-iframe {{ width: 100%; height: calc(100% - 45px); border: none; background: black; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🌐 Student Labs Portal</h1>
            <p>Usuario: <strong>{user}</strong></p>
            
            {"<div class='section'><div class='status'><strong>✅ Lab Activo</strong></div>" + nodes_html + "<button class='danger' onclick='destroyLab()'>Destruir Lab Completo</button></div>" if lab_active else "<div class='section'><h2>Crear Laboratorio de Red</h2><p>Selecciona una topología para comenzar:</p><button onclick=\"createLab('simple-link')\">🔗 Enlace Simple (2 nodos)</button><button onclick=\"createLab('basic-network')\">🌐 Red Básica con Router (3 nodos)</button></div>"}
        </div>
        
        <script>
        function createLab(template) {{
            if(confirm('¿Crear laboratorio con topología ' + template + '?\\n\\nEsto puede tardar 1-2 minutos...')) {{
                const btn = event.target;
                btn.disabled = true;
                btn.textContent = 'Creando...';
                
                fetch('/api/labs/deploy', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    credentials: 'include',
                    body: JSON.stringify({{template: template}})
                }})
                .then(r => r.json())
                .then(data => {{
                    if(data.success) {{
                        alert('✅ Lab creado exitosamente\\n\\nRecarga la página para ver los nodos.');
                        location.reload();
                    }} else {{
                        alert('❌ Error: ' + data.error);
                        btn.disabled = false;
                        btn.textContent = 'Reintentar';
                    }}
                }})
                .catch(err => {{
                    alert('Error de red: ' + err);
                    btn.disabled = false;
                    btn.textContent = 'Reintentar';
                }});
            }}
        }}
        
        function destroyLab() {{
            if(confirm('⚠️ ¿Destruir laboratorio?\\n\\nSe perderán todos los datos y configuraciones.')) {{
                fetch('/api/labs/destroy', {{
                    method: 'POST',
                    credentials: 'include'
                }})
                .then(r => r.json())
                .then(data => {{
                    alert(data.success ? '✅ Lab destruido' : '❌ Error: ' + data.error);
                    location.reload();
                }});
            }}
        }}
        
        function openTerminal(nodeName, url) {{
            // Abrir terminal en iframe usando xterm.js
            const terminal = document.getElementById('terminal-container');
            const iframe = document.getElementById('terminal-iframe');
            const nodeLabel = document.getElementById('terminal-node-label');
            
            iframe.src = url;
            nodeLabel.textContent = nodeName;
            terminal.classList.add('active');
        }}
        
        function closeTerminal() {{
            const terminal = document.getElementById('terminal-container');
            const iframe = document.getElementById('terminal-iframe');
            
            terminal.classList.remove('active');
            iframe.src = '';
        }}
        </script>
        
        <!-- Terminal Container -->
        <div id="terminal-container" class="terminal-container">
            <div class="terminal-header">
                <h4>Terminal: <span id="terminal-node-label"></span></h4>
                <button class="terminal-close" onclick="closeTerminal()">✕ Cerrar</button>
            </div>
            <iframe id="terminal-iframe" class="terminal-iframe"></iframe>
        </div>
    </body>
    </html>
    """

# ============================================
# ContainerLab API Endpoints
# ============================================

@app.route('/api/labs/deploy', methods=['POST'])
def api_deploy_lab():
    """API para desplegar un lab de ContainerLab"""
    user = request.headers.get('Remote-User', 'invitado')
    data = request.get_json()
    template = data.get('template', 'simple-link')
    
    result = clab.deploy_lab(user, template)
    return jsonify(result)

@app.route('/api/labs/destroy', methods=['POST'])
def api_destroy_lab():
    """API para destruir el lab de un usuario"""
    user = request.headers.get('Remote-User', 'invitado')
    result = clab.destroy_lab(user)
    return jsonify(result)

@app.route('/api/labs/status', methods=['GET'])
def api_lab_status():
    """API para ver el estado del lab"""
    user = request.headers.get('Remote-User', 'invitado')
    result = clab.list_labs(user)
    return jsonify(result)

@app.route('/terminal/<username>/<node_name>')
def terminal_page(username, node_name):
    """Página HTML con xterm.js"""
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Terminal - {{node_name}}</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css" />
        <script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js"></script>
        <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
        <style>
            body { margin: 0; padding: 0; background: #000; }
            #terminal { width: 100vw; height: 100vh; }
        </style>
    </head>
    <body>
        <div id="terminal"></div>
        <script>
            const term = new Terminal({
                cursorBlink: true,
                fontSize: 14,
                fontFamily: 'Menlo, Monaco, "Courier New", monospace',
                theme: {
                    background: '#1e1e1e',
                    foreground: '#f0f0f0'
                }
            });
            
            const fitAddon = new FitAddon.FitAddon();
            term.loadAddon(fitAddon);
            term.open(document.getElementById('terminal'));
            fitAddon.fit();
            
            const socket = io({
                path: '/socket.io/'
            });
            
            socket.on('connect', () => {
                console.log('Connected to server');
                socket.emit('start_terminal', {
                    username: '{{username}}',
                    node_name: '{{node_name}}',
                    rows: term.rows,
                    cols: term.cols
                });
            });
            
            socket.on('terminal_output', (data) => {
                term.write(data);
            });
            
            socket.on('terminal_error', (data) => {
                term.write('\\r\\n\\x1b[1;31mError: ' + data.error + '\\x1b[0m\\r\\n');
            });
            
            term.onData((data) => {
                socket.emit('terminal_input', {
                    username: '{{username}}',
                    node_name: '{{node_name}}',
                    data: data
                });
            });
            
            term.onResize((size) => {
                socket.emit('terminal_resize', {
                    username: '{{username}}',
                    node_name: '{{node_name}}',
                    rows: size.rows,
                    cols: size.cols
                });
            });
            
            window.addEventListener('resize', () => {
                fitAddon.fit();
            });
        </script>
    </body>
    </html>
    """, username=username, node_name=node_name)

# Diccionario para mantener sesiones activas
terminal_sessions = {}

@socketio.on('start_terminal')
def handle_start_terminal(data):
    username = data['username']
    node_name = data['node_name']
    rows = data.get('rows', 24)
    cols = data.get('cols', 80)
    
    container_name = f"clab-lab-{username}-{node_name}"
    
    try:
        container = client.containers.get(container_name)
        
        # Crear sesión de terminal usando docker exec
        exec_id = container.client.api.exec_create(
            container.id,
            'sh',
            stdin=True,
            tty=True,
            environment={"TERM": "xterm-256color"},
            workdir='/root'
        )
        
        exec_socket = container.client.api.exec_start(
            exec_id,
            socket=True,
            tty=True
        )
        
        session_id = request.sid
        terminal_sessions[session_id] = {
            'socket': exec_socket,
            'container': container,
            'exec_id': exec_id
        }
        
        # Leer salida en background
        def read_output():
            try:
                while session_id in terminal_sessions:
                    data = exec_socket._sock.recv(1024)
                    if not data:
                        break
                    socketio.emit('terminal_output', data.decode('utf-8', errors='ignore'), room=session_id)
            except:
                pass
            finally:
                if session_id in terminal_sessions:
                    del terminal_sessions[session_id]
        
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
            input_data = data['data']
            terminal_sessions[session_id]['socket']._sock.send(input_data.encode())
        except Exception as e:
            emit('terminal_error', {'error': str(e)})

@socketio.on('terminal_resize')
def handle_terminal_resize(data):
    session_id = request.sid
    if session_id in terminal_sessions:
        try:
            rows = data['rows']
            cols = data['cols']
            exec_id = terminal_sessions[session_id]['exec_id']
            container = terminal_sessions[session_id]['container']
            container.client.api.exec_resize(exec_id, height=rows, width=cols)
        except Exception as e:
            pass

@socketio.on('disconnect')
def handle_disconnect():
    session_id = request.sid
    if session_id in terminal_sessions:
        try:
            terminal_sessions[session_id]['socket']._sock.close()
        except:
            pass
        del terminal_sessions[session_id]

if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', port=5000)