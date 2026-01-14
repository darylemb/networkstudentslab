import os
import subprocess  # nosec: B404
import yaml


def get_available_ports(count):
    """Obtiene puertos disponibles para los nodos"""
    import socket
    ports = []
    for _ in range(count):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.listen(1)
            port = s.getsockname()[1]
            ports.append(port)
    return ports


def deploy_lab(username, template_name, network_name="lab-net", ipv4_subnet=None):
    """Despliega un lab de ContainerLab para un usuario"""
    lab_name = f"lab-{username}"
    lab_dir = f"/labs/{username}"
    os.makedirs(lab_dir, exist_ok=True)

    # Leer template
    template_path = f"/lab-templates/{template_name}.yml"
    with open(template_path, 'r') as f:
        topology = yaml.safe_load(f)

    # Contar nodos para asignar puertos
    node_count = len(topology['topology']['nodes'])
    ports = get_available_ports(node_count)

    # Actualizar puertos en la topología
    port_mapping = {}
    for idx, (node_name, node_config) in enumerate(topology['topology']['nodes'].items()):
        port = ports[idx]
        port_mapping[node_name] = port

        # Actualizar configuración del nodo
        if 'ports' not in node_config:
            node_config['ports'] = []
        node_config['ports'].append(f"{port}:7681")

    # Forzar red de administración aislada
    if 'mgmt' not in topology:
        topology['mgmt'] = {}
    topology['mgmt']['network'] = network_name
    # ELIMINAR subred del template para usar la nueva o dejar que Docker asigne
    if 'ipv4-subnet' in topology['mgmt']:
        del topology['mgmt']['ipv4-subnet']
    
    # Asignar subred explícita si se provee (recomendado para evitar colisiones entre redes aisladas)
    if ipv4_subnet:
        topology['mgmt']['ipv4-subnet'] = ipv4_subnet

    # Guardar configuración actualizada
    topology['name'] = lab_name
    config_path = f"{lab_dir}/topology.yml"
    with open(config_path, 'w') as f:
        yaml.dump(topology, f, default_flow_style=False)

    # Desplegar con containerlab
    try:
        result = subprocess.run(  # nosec: B603 B607
            ['containerlab', 'deploy', '-t', config_path],
            capture_output=True,
            text=True,
            check=True,
            cwd=lab_dir
        )

        # Retornar info de nodos y puertos
        nodes_info = {}
        for node_name, port in port_mapping.items():
            nodes_info[node_name] = {
                'port': port,
                'url': f'/labs/{username}/{node_name}'
            }

        # Guardar mapeo de puertos para el proxy
        port_map_file = f"{lab_dir}/ports.yml"
        with open(port_map_file, 'w') as f:
            yaml.dump(port_mapping, f)

        return {
            'success': True,
            'lab_name': lab_name,
            'nodes': nodes_info,
            'topology': topology,
            'ports': port_mapping,
            'message': result.stdout
        }
    except subprocess.CalledProcessError as e:
        return {
            'success': False,
            'error': e.stderr
        }


def destroy_lab(username):
    """Destruye el lab de un usuario"""
    lab_dir = f"/labs/{username}"
    config_path = f"{lab_dir}/topology.yml"

    if not os.path.exists(config_path):
        return {'success': False, 'error': 'Lab no existe'}

    try:
        subprocess.run(  # nosec: B603 B607
            ['containerlab', 'destroy', '-t', config_path, '--cleanup'],
            capture_output=True,
            text=True,
            check=True
        )
        return {'success': True}
    except subprocess.CalledProcessError as e:
        return {'success': False, 'error': e.stderr}


def list_labs(username):
    """Lista los labs de un usuario"""
    lab_name = f"lab-{username}"
    try:
        result = subprocess.run(  # nosec: B603 B607
            ['containerlab', 'inspect', '--name', lab_name, '--format', 'json'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            import json
            data = json.loads(result.stdout)
            
            # El formato JSON de clab es { "lab-name": [ {node1}, {node2} ] }
            # Buscamos la lista de nodos para el lab-name
            nodes = data.get(lab_name, [])
            network_info = {
                'nodes': {},
                'subnet': 'Desconocida'
            }
            
            for node in nodes:
                # El nombre viene como clab-lab-username-nodename
                full_name = node.get('name', '')
                short_name = full_name.replace(f"clab-{lab_name}-", "")
                
                network_info['nodes'][short_name] = {
                    'ipv4': node.get('ipv4_address', 'N/A').split('/')[0], # Solo la IP sin la máscara
                    'container_name': full_name
                }
            
            return {'success': True, 'data': network_info}
        return {'success': False, 'error': 'Lab no encontrado'}
    except Exception as e:
        return {'success': False, 'error': str(e)}


def get_node_port(username, node_name):
    """Obtiene el puerto de un nodo específico"""
    lab_dir = f"/labs/{username}"
    port_map_file = f"{lab_dir}/ports.yml"

    if not os.path.exists(port_map_file):
        return None

    with open(port_map_file, 'r') as f:
        port_mapping = yaml.safe_load(f)

    return port_mapping.get(node_name)
