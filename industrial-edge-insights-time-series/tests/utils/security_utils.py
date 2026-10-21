#
# Apache v2 license
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#

import subprocess  # nosec B404 - exec_command explicitly disables shell execution
import json
import time
import os
import sys
import aiohttp
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../utils')))
import common_utils
import yaml
import secrets
import string
from ruamel.yaml import YAML
import logging
import re
import asyncio
from decimal import Decimal, InvalidOperation
import constants
from influxdb_client import InfluxDBClient
import pandas as pd

# Set up logger
logger = logging.getLogger(__name__)

async def login_to_grafana(url, username, password):
    """
    Simple Grafana authentication test using the API endpoint.
    
    Args:
        url: Grafana URL
        username: Grafana username  
        password: Grafana password
        
    Returns:
        bool: True if credentials are valid, False otherwise
    """
    import ssl
    try:
        # Create SSL context that doesn't verify certificates for self-signed certs
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            # Simple API authentication test - just verify credentials work
            async with session.get(f"{url}/api/user", 
                                   auth=aiohttp.BasicAuth(username, password),
                                   timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    logger.info("Grafana authentication successful")
                    return True
                else:
                    logger.error(f"Grafana authentication failed: HTTP {response.status}")
                    return False
    except Exception as e:
        logger.error(f"Grafana authentication error: {e}")
        return False


def find_exposed_ports_docker():
    # Run the docker ps command and capture the output
    result = common_utils.exec_command(
        ["docker", "ps", "--format", "table {{.Names}}\t{{.Ports}}"],
        capture_output=True,
        text=True
    )

    # Filter lines that start with 'ia-' to get relevant containers
    lines = [line for line in result.stdout.splitlines() if line.startswith("ia-")]

    # Initialize a dictionary to store exposed ports for each container
    exposed_ports = {}

    for line in lines:
        # Split the line into container name and ports using regex to handle variable spacing
        import re
        # Match container name (starts with ia-) followed by any whitespace, then capture the rest as ports
        match = re.match(r'(ia-\S+)\s+(.*)', line)
        if match:
            container_name = match.group(1)
            ports = match.group(2) if match.group(2) else ""
        else:
            # Fallback to tab split if regex doesn't match
            parts = line.split('\t')
            container_name = parts[0].strip()
            ports = parts[1].strip() if len(parts) > 1 else ""

        # Initialize a list to store exposed ports for the current container
        exposed_ports[container_name] = []

        # Split the ports by comma and check each one
        for port in ports.split(','):
            port = port.strip()
            # A published port mapping always has the form <bind-address>:<host-port>-><container-port>.
            # The bind address may be 0.0.0.0, :::, or a specific IP (e.g. HOST_IP), so match on '->'
            # rather than a specific address.
            if '->' in port:
                exposed_ports[container_name].append(port)

    # Print the exposed ports for each container
    logger.info("Exposed ports:")
    logger.info("------------------")
    for container, ports in exposed_ports.items():
        if ports:
            logger.info(f"{container}: {', '.join(ports)}")
        else:
            logger.info(f"{container}: No exposed ports")

    return exposed_ports

def check_open_ports(target):
    try:
        # Execute the nmap command to check for open ports
        result = common_utils.exec_command(['nmap', '-p-', target], capture_output=True, text=True)

        # Print the nmap command response
        logger.info(result.stdout)
        # Analyze the output to determine if there are open ports
        if "open" in result.stdout:
            return False
        else:
            return True
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return False

def check_nmap_docker(target, ports):
    """Docker-specific nmap checking function that handles Docker port format."""
    try:
        # Extract actual port numbers from the exposed ports data
        port_numbers = []
        
        # Handle case where ports is a dictionary (from Docker exposed ports)
        if isinstance(ports, dict):
            logger.info(f"Debug: Processing exposed ports dictionary: {ports}")
            for container, port_mappings in ports.items():
                logger.info(f"Debug: Container {container} has port mappings: {port_mappings}")
                for port_mapping in port_mappings:
                    # Extract port numbers from strings like "0.0.0.0:3000->3000/tcp"
                    import re
                    matches = re.findall(r':(\d+)->', port_mapping)
                    logger.info(f"Debug: Found port matches in '{port_mapping}': {matches}")
                    port_numbers.extend(matches)
        else:
            logger.error(f"Unexpected ports format: {type(ports)}")
            return False
        
        logger.info(f"Debug: Final extracted port numbers: {port_numbers}")
        
        if not port_numbers:
            logger.warning("No ports found to scan")
            # For Docker deployments, check default exposed ports (nginx proxy)
            # From docker-compose.yml: nginx exposes GRAFANA_PORT:15443 (HTTPS)
            default_ports = ["3000"]  # Default Docker exposed ports
            logger.info(f"Using default Docker exposed ports: {default_ports}")
            port_numbers = default_ports
            
        # Execute the nmap command to check for open ports
        port_list = ','.join(port_numbers)
        logger.info(f"Scanning ports {port_list} on target {target}")
        result = common_utils.exec_command(['nmap', '-p', port_list, target], capture_output=True, text=True)

        # Print the nmap command response
        logger.info(result.stdout)

        # Analyze the output to determine if there are open ports
        if "open" in result.stdout:
            return True
        else:
            return False
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return False

def _replace_in_file(file_path, old_text, new_text):
    """Replace the first occurrence of ``old_text`` with ``new_text`` in ``file_path``."""
    with open(file_path, "r", encoding="utf-8") as handle:
        content = handle.read()

    if old_text not in content:
        raise ValueError(f"Expected text not found in {file_path}")

    with open(file_path, "w", encoding="utf-8") as handle:
        handle.write(content.replace(old_text, new_text, 1))

def update_continuous_simulator_ingestion():
    try:
        # Update the line in the opcua simulator file
        opcua_file = os.path.join(constants.EDGE_AI_SUITES_DIR, "simulator", "opcua-server", "opcua_server.py")
        _replace_in_file(
            opcua_file,
            'continuous_simulator_ingestion = (os.getenv("CONTINUOUS_SIMULATOR_INGESTION", "true")).lower()',
             'continuous_simulator_ingestion = (os.getenv("CONTINUOUS_SIMULATOR_INGESTION", "false")).lower()',
        )
        logger.info(f"Updated 'CONTINUOUS_SIMULATOR_INGESTION' to 'false' in opcua file {opcua_file}.")

        # Update the line in the mqtt publisher file
        mqtt_file = os.path.join(constants.EDGE_AI_SUITES_DIR, "simulator", "mqtt-publisher", "publisher.py")
        _replace_in_file(
            mqtt_file,
            'continuous_simulator_ingestion = os.getenv("CONTINUOUS_SIMULATOR_INGESTION", "true").lower()',
             'continuous_simulator_ingestion = os.getenv("CONTINUOUS_SIMULATOR_INGESTION", "false").lower()',
        )
        logger.info(f"Updated 'CONTINUOUS_SIMULATOR_INGESTION' to 'false' in mqtt file {mqtt_file}.")
    except (OSError, ValueError) as e:
        logger.error(f"An error occurred while updating the file: {e}")

def verify_docker_file_integrity():
    try:
        docker_compose_path = constants.EDGE_AI_SUITES_DIR + "/docker-compose.yml"
        logger.info(f"Reading docker-compose file from: {docker_compose_path}")
        with open(docker_compose_path, "r") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        logger.info(f"Error reading docker-compose.yml: {e}")
        return False
    # Assume all services should have read_only: true
    all_services_read_only = True
    for service_name, service in data.get("services", {}).items():
        if service_name.startswith("ia-"):
            logger.info(f"Checking service with 'ia-' prefix: {service_name}")
            if service.get("read_only", False) is True:
                logger.info(f"Service '{service_name}' has read_only: true")
            else:
                logger.error(f"Service '{service_name}' does not have read_only: true")
                all_services_read_only = False
        else:
            logger.info(f"Service '{service_name}' is not an ia- service.")

    if all_services_read_only:
        logger.info("Docker file verification PASSED: All 'ia-' services have 'read_only: true'.")
        return True
    else:
        logger.error("Docker file verification FAILED: At least one 'ia-' service does not have 'read_only: true'.")
        return False

def extract_docker_exposed_ports():
    """
    Extract port numbers from Docker exposed ports for nmap scanning.
    
    Returns:
        list: List of integer port numbers that are exposed
    """
    try:
        exposed_ports_dict = find_exposed_ports_docker()
        if not exposed_ports_dict:
            return []
        
        ports = []
        for container_name, port_list in exposed_ports_dict.items():
            for port_info in port_list:
                # Extract port from format "0.0.0.0:8086->8086/tcp"
                if '->' in port_info:
                    external_port = port_info.split('->')[0].split(':')[-1]
                    ports.append(int(external_port))
        
        # Remove duplicates and return
        return list(set(ports))
        
    except Exception as e:
        logger.error(f"Error extracting Docker exposed ports: {e}")
        return []

def fetch_docker_credentials(credential_type):
    """
    Fetch credentials from .env file for Docker deployment.
    
    Args:
        credential_type (str): Type of credentials to fetch ('influxdb' or 'grafana')
        
    Returns:
        tuple: (username, password) or (None, None) if not found
    """
    try:
        env_path = os.path.join(constants.EDGE_AI_SUITES_DIR, ".env")
        logger.info(f"Fetching {credential_type} credentials from: {env_path}")

        with open(env_path, 'r') as file:
            lines = file.readlines()

        if credential_type == "influxdb":
            username_key = "INFLUXDB_USERNAME="
            password_key = "INFLUXDB_PASSWORD="  # nosec B105 - this is an environment variable name
        elif credential_type == "grafana":
            username_key = "VISUALIZER_GRAFANA_USER="
            password_key = "VISUALIZER_GRAFANA_PASSWORD="  # nosec B105 - this is an environment variable name
        else:
            logger.error(f"Unknown credential type: {credential_type}")
            return None, None

        username = None
        password = None
        
        for line in lines:
            line = line.strip()
            if line.startswith(username_key):
                username = line.split('=', 1)[1]
            elif line.startswith(password_key):
                password = line.split('=', 1)[1]

        username = os.environ.get(username_key[:-1], username)
        password = os.environ.get(password_key[:-1], password)
        
        # Note: Not logging credentials for security reasons  
        logger.info(f"Successfully retrieved {credential_type.upper()} credentials from .env file")
        return username, password
        
    except FileNotFoundError:
        logger.error(f"File not found: {env_path}")
        return None, None
    except Exception as e:
        logger.error(f"Error fetching {credential_type} credentials: {e}")
        return None, None

def influxdb_login_docker(container_name="ia-influxdb"):
    """Execute InfluxDB commands inside the Docker container to verify authentication."""
    logger.info(f"Testing InfluxDB authentication in Docker container '{container_name}'...")
    try:
        # Get InfluxDB credentials from .env file
        influxdb_username, influxdb_password = fetch_docker_credentials("influxdb")
        
        if not influxdb_username or not influxdb_password:
            logger.error("Failed to get InfluxDB credentials from .env file.")
            return False

        # Use environment variable to pass password securely to InfluxDB CLI
        # The InfluxDB CLI reads INFLUX_PASSWORD from environment
        logger.info(f"Executing InfluxDB command - 'SHOW MEASUREMENTS'  in container '{container_name}' with configured credentials (credentials not shown)")
        
        result = common_utils.exec_command(
            [
                "docker", "exec", "-e", f"INFLUX_PASSWORD={influxdb_password}", container_name,
                "influx", "-username", influxdb_username, "-database", "datain",
                "-execute", "SHOW MEASUREMENTS"
            ],
            capture_output=True, text=True
        )
        response = result.stdout.strip()
        error_output = result.stderr.strip()
        
        logger.info(f"InfluxDB command exit code: {result.returncode}")
        if response:
            logger.info(f"InfluxDB response: {response}")
        if error_output:
            logger.info(f"InfluxDB stderr: {error_output}")
        
        # Check if command was successful - returncode 0 means authentication worked
        if result.returncode == 0:
            logger.info("InfluxDB Docker authentication successful.")
            return True
        else:
            logger.error(f"InfluxDB Docker authentication failed with exit code: {result.returncode}")
            return False
            
    except subprocess.CalledProcessError as e:
        logger.error(f"InfluxDB Docker login command failed: {e.stderr}")
        return False
    except Exception as e:
        logger.error(f"Error during InfluxDB Docker login: {e}")
        return False

async def login_to_grafana_docker(port=3000):
    """Login to Grafana running in Docker container on specified port."""
    try:
        # Get Grafana credentials from .env file
        grafana_username, grafana_password = fetch_docker_credentials("grafana")
        
        if not grafana_username or not grafana_password:
            logger.error("Failed to get Grafana credentials from .env file.")
            return False
        
        # For Docker deployment, Grafana is accessible via nginx proxy on HTTPS
        # The nginx service exposes ${GRAFANA_PORT}:443 (HTTPS)
        # Only test HTTPS path - HTTP working would be a security bug
        grafana_url = f"https://localhost:{port}"
        
        logger.info(f"Attempting to login to Grafana at: {grafana_url}")
        
        # Use the existing Grafana login function
        result = await login_to_grafana(grafana_url, grafana_username, grafana_password)
        if result:
            return True
        
        logger.error("Failed to login to Grafana via HTTPS")
        return False
        
    except Exception as e:
        logger.error(f"Error during Grafana Docker login: {e}")
        return False


# Port Utilities

def read_env_file(env_file_path: str):
    """
    Read environment variables from .env file.
    
    Args:
        env_file_path: Path to the .env file
        
    Returns:
        Dictionary of environment variables
    """
    env_vars = {}
    
    try:
        with open(env_file_path, 'r') as file:
            for line in file:
                line = line.strip()
                # Skip comments and empty lines
                if line and not line.startswith('#'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        env_vars[key.strip()] = value.strip()
        for key in env_vars:
            if key in os.environ:
                env_vars[key] = os.environ[key]
    except FileNotFoundError:
        logger.warning(f".env file not found at {env_file_path}")
    
    return env_vars


def get_docker_ports_from_env(project_root: str = None):
    """
    Get Docker port mappings from .env file.
    
    Args:
        project_root: Root directory of the project
        
    Returns:
        Dictionary mapping service names to port numbers
    """
    if project_root is None:
        # Default to the wind turbine project directory
        project_root = "/home/user/WW35_NMAP/frameworks.ai.ai-suite-for-timeseries/edge-ai-suites/manufacturing-ai-suite/wind-turbine-anomaly-detection"
    
    env_file_path = os.path.join(project_root, ".env")
    env_vars = read_env_file(env_file_path)
    
    # Map environment variable names to service names
    port_mapping = {}
    
    # Port mappings from .env: GRAFANA_PORT, OPCUA_SERVER_PORT, plus hardcoded TSAM 5000 and MQTT 1883
    
    if 'GRAFANA_PORT' in env_vars:
        port_mapping['grafana'] = int(env_vars['GRAFANA_PORT'])
    
    if 'OPCUA_SERVER_PORT' in env_vars:
        port_mapping['opcua'] = int(env_vars['OPCUA_SERVER_PORT'])
    else:
        port_mapping['opcua'] = constants.OPCUA_SERVER_PORT  # Default internal port for OPC UA server
    
    # These are hardcoded in docker-compose.yml
    port_mapping['mqtt'] = 1883
    port_mapping['time_series_analytics'] = 5000
    
    return port_mapping


def parse_docker_compose_ports(docker_compose_path: str):
    """
    Parse port mappings from docker-compose.yml file.
    
    Args:
        docker_compose_path: Path to docker-compose.yml file
        
    Returns:
        Dictionary mapping service names to list of exposed ports
    """
    ports_by_service = {}
    
    try:
        with open(docker_compose_path, 'r') as file:
            compose_data = yaml.safe_load(file)
        
        if 'services' in compose_data:
            for service_name, service_config in compose_data['services'].items():
                if 'ports' in service_config:
                    service_ports = []
                    for port_mapping in service_config['ports']:
                        # Handle different port mapping formats
                        if isinstance(port_mapping, str):
                            # Format: "5000:5000" or "1883:1883"
                            if ':' in port_mapping:
                                host_port = port_mapping.split(':')[0]
                                # Remove any environment variable syntax
                                host_port = re.sub(r'^\$\{.*\}$', '', host_port)
                                if host_port.isdigit():
                                    service_ports.append(int(host_port))
                        elif isinstance(port_mapping, int):
                            service_ports.append(port_mapping)
                    
                    if service_ports:
                        # Simplify service name (remove ia- prefix)
                        simple_name = service_name.replace('ia-', '').replace('-', '_')
                        ports_by_service[simple_name] = service_ports
    
    except FileNotFoundError:
        logger.warning(f"docker-compose.yml not found at {docker_compose_path}")
    except yaml.YAMLError as e:
        logger.warning(f"Error parsing docker-compose.yml: {e}")
    
    return ports_by_service


def get_docker_ports_from_compose(project_root: str = None):
    """
    Get Docker port mappings by parsing docker-compose.yml and .env files.
    
    Args:
        project_root: Root directory of the project
        
    Returns:
        Dictionary mapping service names to port numbers
    """
    if project_root is None:
        project_root = "/home/user/WW35_NMAP/frameworks.ai.ai-suite-for-timeseries/edge-ai-suites/manufacturing-ai-suite/wind-turbine-anomaly-detection"
    
    docker_compose_path = os.path.join(project_root, "docker-compose.yml")
    env_vars = read_env_file(os.path.join(project_root, ".env"))
    
    # Parse docker-compose.yml for port mappings
    ports_by_service = parse_docker_compose_ports(docker_compose_path)
    
    # Create final port mapping
    port_mapping = {}
    
    # Get ports from parsed compose file
    for service, ports in ports_by_service.items():
        if ports:
            port_mapping[service] = ports[0]  # Take first port if multiple
    
    # Handle environment variable substitutions
    if 'grafana' in port_mapping and 'GRAFANA_PORT' in env_vars:
        port_mapping['grafana'] = int(env_vars['GRAFANA_PORT'])
    
    if 'opcua_server' in port_mapping and 'OPCUA_SERVER_PORT' in env_vars:
        port_mapping['opcua'] = int(env_vars['OPCUA_SERVER_PORT'])
    else:
        port_mapping['opcua'] = constants.OPCUA_SERVER_PORT  # Default internal port for OPC UA server
    
    return port_mapping


def get_dynamic_ports(project_root: str = None):
    """
    Get port numbers dynamically from configuration files.
    This is the main function to use instead of hardcoded ports.
    
    Args:
        project_root: Root directory of the project
    
    Returns:
        Dictionary with port mappings: {'grafana': 3000, 'mqtt': 1883, ...}
    """
    try:
        # Try to get ports from docker-compose and .env files
        ports = get_docker_ports_from_compose(project_root)
        
        # Ensure we have all required ports with fallback values
        default_ports = {
            'grafana': 3000,
            'mqtt': 1883,
            'time_series_analytics': 5000,
            'opcua': 4840  # Internal port, not the exposed port
        }
        
        # Merge with defaults for any missing ports
        for service, default_port in default_ports.items():
            if service not in ports:
                ports[service] = default_port
        
        return ports
        
    except Exception as e:
        logger.warning(f"Could not read dynamic ports, using defaults: {e}")
        # Fallback to default ports
        return {
            'grafana': 3000,
            'mqtt': 1883,
            'time_series_analytics': 5000,
            'opcua': 4840
        }


def get_ports_for_environment(environment: str = "docker", project_root: str = None):
    """
    Get port numbers based on the deployment environment.
    
    Args:
        environment: "docker"
        project_root: Root directory of the project
        
    Returns:
        Dictionary of port numbers for the given environment
    """
    if environment.lower() == "docker":
        # For Docker, return dynamic ports from config files
        return get_dynamic_ports(project_root)
    else:
        logger.error(f"Unknown environment: {environment}")
        return {}
