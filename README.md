# 🧪 Student Labs - Provisioning Portal

Una plataforma moderna basada en la web para el despliegue dinámico y la gestión de laboratorios de redes utilizando **ContainerLab** y **Docker**.

## 🚀 Características Principales

### Para Estudiantes / Usuarios
- **Autenticación Segura**: Sistema de registro e inicio de sesión con Argon2.
- **Despliegue On-Demand**: Elige una plantilla de red y despliega tu laboratorio físico en segundos.
- **Interfaz de Terminal Avanzada**:
  - **Multi-Terminal**: Soporte para múltiples pestañas de terminales persistentes.
  - **Modo Cuadrícula**: Visualiza todos tus nodos simultáneamente.
  - **Responsive & Resizable**: Panel de terminales redimensionable verticalmente.
- **Mapeo de Puertos**: Vista clara de los puertos asignados para conexiones externas (SSH, HTTP, etc.).

### Para Administradores (🛡️ Dashboard)
- **Gestión de Usuarios y Labs**: Lista completa de usuarios y laboratorios activos con opciones de destrucción forzada.
- **Métricas en Tiempo Real**: Visualización asíncrona de consumo de **CPU** y **RAM** por contenedor.
- **Visibilidad de Red**: Acceso rápido a las direcciones IP IPv4 de administración de cada nodo.
- **Optimización**: Carga asíncrona de recursos para un panel administrativo extremadamente rápido.

## 🛠️ Requisitos Previos

- Docker y Docker Compose
- ContainerLab instalado en el host (el portal interactúa con él mediante el socket de Docker)

## ⚙️ Configuración e Instalación

1. **Clonar el repositorio y configurar variables**:
   ```bash
   cp env.example .env
   # Edita .env con tus credenciales preferidas
   ```

2. **Levantar la infraestructura**:
   ```bash
   docker compose up -d --build
   ```

3. **Promover un Administrador**:
   Regístrate normalmente en la web y luego ejecuta:
   ```bash
   docker exec -it student-labs-portal-1 python promote_admin.py <tu_username>
   ```

## 📂 Estructura del Proyecto

- `/provisioning-portal`: Aplicación Flask (Backend) y motor de plantillas (Frontend).
- `/lab-templates`: Directorio para los archivos YAML de ContainerLab que sirven de plantilla.
- `/labs`: Directorio donde se almacenan los datos dinámicos de los usuarios (volumen persistente).
- `/nginx`: Configuración del proxy inverso para el tráfico web y Websockets.

## 🔒 Arquitectura de Seguridad

- **Aislamiento**: Cada laboratorio se despliega en su propio subdirectorio con prefijos de nombre únicos.
- **Sesiones**: Cookies seguras y HTTPOnly con tiempo de vida configurable.
- **Base de Datos**: PostgreSQL para la persistencia del estado de los laboratorios y usuarios.

---
*Desarrollado para la simplificación de laboratorios de networking e infraestructura.*
