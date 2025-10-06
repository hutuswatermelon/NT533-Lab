#####################################################################################
# API Access
# Service	    Endpoint
# Compute       https://cloud-compute.uitiot.vn/v2.1/3b1a61462c4b4bd69ff85850ced7462d
# Identity      https://cloud-identity.uitiot.vn/v3/
# Image         https://cloud-image.uitiot.vn
# Load Balancer	https://cloud-loadbalancer.uitiot.vn
# Network	    https://cloud-network.uitiot.vn
# Placement	    https://cloud-placement.uitiot.vn
#####################################################################################
import base64
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
import openstack
import getpass
from openstack import exceptions as os_exceptions
import queue
import os

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret")

# --- Fixed Configuration ---
GROUP_NAME = "nhom02"
NET_NAME = f"{GROUP_NAME}_net"
SUBNET_NAME = f"{GROUP_NAME}_subnet"
ROUTER_NAME = f"{GROUP_NAME}_router"
CIDR = "192.168.2.0/24"
IMAGE_NAME = "Ubuntu 22.04"
FLAVOR_NAME = "d10.xs1"
KEYPAIR_NAME = "Nhom02Key"
EXT_NET_NAME = "Public_Net"
DNS_NAMESERVERS = ["8.8.8.8", "1.1.1.1"]

LOAD_BALANCER_NAME = f"{GROUP_NAME}_lb"
LISTENER_NAME = f"{GROUP_NAME}_listener"
POOL_NAME = f"{GROUP_NAME}_pool"
HEALTH_MONITOR_NAME = f"{GROUP_NAME}_hm"

MAX_INSTANCES = 5

DEFAULT_USERDATA = """#cloud-config
password: "12345678"
chpasswd:
    expire: False
ssh_pwauth: True

package_update: true
package_upgrade: true
packages:
    - apache2

runcmd:
    - systemctl enable apache2
    - systemctl start apache2
    - bash -c 'echo "Group 02 - $(hostname -I)" > /var/www/html/index.html'
"""

STATUS_LABEL = {
        "BUILD": "Provisioning",
        "ACTIVE": "Active",
        "ERROR": "Error"
}

# --- Connect to OpenStack ---
print("Connecting to OpenStack")
username = os.getenv("OS_USERNAME")
print(f"Username: {username}")
password = getpass.getpass("Enter your OpenStack password: ")
conn = openstack.connect(cloud='openstack', password=password)

# --- Event Queue for SSE ---
subscriptions = set()
event_queue = queue.Queue()


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def encode_user_data(script_text: str) -> str:
        """Encode user_data script to base64"""
        return base64.b64encode(script_text.encode("utf-8")).decode("utf-8")


def get_fixed_ip(server):
        """Get fixed IP of server"""
        addresses = getattr(server, "addresses", {}) or {}
        for addr_list in addresses.values():
                for addr in addr_list:
                        if addr.get("OS-EXT-IPS:type") == "fixed":
                                return addr.get("addr")
        return None


def get_floating_ip(server):
        """Get floating IP of server"""
        addresses = getattr(server, "addresses", {}) or {}
        for addr_list in addresses.values():
                for addr in addr_list:
                        if addr.get("OS-EXT-IPS:type") == "floating":
                                return addr.get("addr")
        return None


def readable_status(server):
        """Convert status to readable format"""
        return STATUS_LABEL.get(server.status, server.status)


def summarize_server(server):
        """Summarize server information"""
        return {
                "id": server.id,
                "name": server.name,
                "status": server.status,
                "display_status": readable_status(server),
                "fixed_ip": get_fixed_ip(server),
                "floating_ip": get_floating_ip(server)
        }


def push_refresh():
        """Send refresh event to all clients"""
        for q in list(subscriptions):
                q.put("refresh")


# ============================================================================
# NETWORK INFRASTRUCTURE FUNCTIONS
# ============================================================================

def create_network_infra():
        """Create network, subnet and router"""
        # Create/update network
        net = conn.network.find_network(NET_NAME)
        if not net:
                net = conn.network.create_network(
                        name=NET_NAME,
                        port_security_enabled=False
                )
        else:
                if getattr(net, "port_security_enabled", True):
                        net = conn.network.update_network(net, port_security_enabled=False)
        
        # Create subnet
        subnet = conn.network.find_subnet(SUBNET_NAME)
        if not subnet:
                subnet = conn.network.create_subnet(
                        name=SUBNET_NAME,
                        network_id=net.id,
                        ip_version=4,
                        cidr=CIDR,
                        gateway_ip=CIDR.replace("0/24", "1"),
                        dns_nameservers=DNS_NAMESERVERS
                )
        
        # Create/update router
        router = conn.network.find_router(ROUTER_NAME)
        if not router:
                ext_net = conn.network.find_network(EXT_NET_NAME)
                router = conn.network.create_router(
                        name=ROUTER_NAME,
                        external_gateway_info={"network_id": ext_net.id}
                )
                conn.network.add_interface_to_router(router, subnet_id=subnet.id)
        elif subnet:
                ext_net = conn.network.find_network(EXT_NET_NAME)
                if not router.external_gateway_info or router.external_gateway_info.get("network_id") != ext_net.id:
                        router = conn.network.update_router(router, external_gateway_info={"network_id": ext_net.id})
                try:
                        conn.network.add_interface_to_router(router, subnet_id=subnet.id)
                except (os_exceptions.BadRequestException, os_exceptions.ConflictException):
                        pass
        
        return net, subnet, router


# ============================================================================
# FLOATING IP FUNCTIONS
# ============================================================================

def allocate_floating_ip(server):
        """Allocate floating IP for server"""
        ext_net = conn.network.find_network(EXT_NET_NAME)
        if not ext_net:
                raise RuntimeError(f"External network '{EXT_NET_NAME}' not found.")
        
        ports = list(conn.network.ports(device_id=server.id))
        if not ports:
                raise RuntimeError(f"No port found for server {server.name}.")

        # Find unused floating IP
        reusable_fip = None
        for ip in conn.network.ips():
                if (getattr(ip, "floating_network_id", None) == ext_net.id
                        and getattr(ip, "port_id", None) is None):
                        reusable_fip = ip
                        break

        if reusable_fip:
                conn.network.update_ip(reusable_fip, port_id=ports[0].id)
                return conn.network.get_ip(reusable_fip.id)

        # Create new floating IP
        fip = conn.network.create_ip(floating_network_id=ext_net.id)
        conn.network.update_ip(fip, port_id=ports[0].id)
        return conn.network.get_ip(fip.id)


def detach_floating_ip(server):
        """Detach floating IP from server"""
        floating_ip = get_floating_ip(server)
        if not floating_ip:
                return None
        
        fip = conn.network.find_ip(floating_ip, ignore_missing=True)
        if not fip:
                return None
        
        if getattr(fip, "port_id", None):
                conn.network.update_ip(fip, port_id=None)
        
        return fip


# ============================================================================
# VM MANAGEMENT FUNCTIONS
# ============================================================================

def create_vm(name, user_data_script=None):
        """Create new VM"""
        net = conn.network.find_network(NET_NAME)
        if not net:
                raise RuntimeError("Network infrastructure is not initialized. Please click 'Initialize Network' first.")
        subnet = conn.network.find_subnet(SUBNET_NAME)
        if not subnet:
                raise RuntimeError("Subnet is not initialized. Please click 'Initialize Network' first.")
        
        # Find image
        image = conn.compute.find_image(IMAGE_NAME, ignore_missing=True)
        if not image:
                raise RuntimeError(f"Image '{IMAGE_NAME}' not found.")
        
        # Find flavor
        flavor = conn.compute.find_flavor(FLAVOR_NAME, ignore_missing=True)
        if not flavor:
                raise RuntimeError(f"Flavor '{FLAVOR_NAME}' not found.")
        
        # Find keypair
        keypair = conn.compute.find_keypair(KEYPAIR_NAME)
        if not keypair:
                raise RuntimeError(f"Keypair '{KEYPAIR_NAME}' not found.")
        
        # Prepare user_data
        script = (user_data_script or DEFAULT_USERDATA).strip() or DEFAULT_USERDATA
        
        # Create port
        port = conn.network.create_port(
                name=f"{name}_port",
                network_id=net.id,
                port_security_enabled=False
        )
        
        try:
                # Create server
                server = conn.compute.create_server(
                        name=name,
                        image_id=image.id,
                        flavor_id=flavor.id,
                        networks=[{"port": port.id}],
                        key_name=keypair.name,
                        user_data=encode_user_data(script),
                        security_groups=[{"name": "default"}]
                )
                server = conn.compute.wait_for_server(server)
        except Exception:
                conn.network.delete_port(port, ignore_missing=True)
                raise
        
        # Allocate floating IP
        fip = allocate_floating_ip(server)
        server = conn.compute.get_server(server.id)

        try:
                register_server_with_lb(server, subnet.id)
        except Exception as exc:
                print(f"Failed to register server {server.name} with load balancer: {exc}")
        
        return server, fip.floating_ip_address


# ============================================================================
# LOAD BALANCER FUNCTIONS (Currently disabled)
# ============================================================================

def get_lb_resources():
        """Get existing load balancer resources"""
        lb = conn.load_balancer.find_load_balancer(LOAD_BALANCER_NAME)
        listener = conn.load_balancer.find_listener(LISTENER_NAME) if lb else None
        pool = conn.load_balancer.find_pool(POOL_NAME) if lb else None
        return lb, listener, pool


def get_lb_floating_ip(lb):
        """Return floating IP attached to load balancer VIP port"""
        vip_port_id = getattr(lb, "vip_port_id", None)
        if not vip_port_id:
                return None
        for ip in conn.network.ips(port_id=vip_port_id):
                return getattr(ip, "floating_ip_address", None)
        return None

def ensure_load_balancer(subnet_id):
        """Ensure load balancer exists"""
        lb = conn.load_balancer.find_load_balancer(LOAD_BALANCER_NAME)
        if not lb:
                lb = conn.load_balancer.create_load_balancer(
                        name=LOAD_BALANCER_NAME,
                        vip_subnet_id=subnet_id
                )
        conn.load_balancer.wait_for_load_balancer(lb.id)
        lb = conn.load_balancer.get_load_balancer(lb.id)

        listener = conn.load_balancer.find_listener(LISTENER_NAME)
        if not listener:
                listener = conn.load_balancer.create_listener(
                        name=LISTENER_NAME,
                        loadbalancer_id=lb.id,
                        protocol="HTTP",
                        protocol_port=80
                )
        conn.load_balancer.wait_for_load_balancer(lb.id)
        listener = conn.load_balancer.get_listener(listener.id)

        pool = conn.load_balancer.find_pool(POOL_NAME)
        if not pool:
                pool = conn.load_balancer.create_pool(
                        name=POOL_NAME,
                        loadbalancer_id=lb.id,
                        listener_id=listener.id,
                        protocol="HTTP",
                        lb_algorithm="ROUND_ROBIN"
                )
                conn.load_balancer.create_health_monitor(
                        name=HEALTH_MONITOR_NAME,
                        pool_id=pool.id,
                        type="HTTP",
                        delay=5,
                        timeout=3,
                        max_retries=3,
                        url_path="/"
                )
        conn.load_balancer.wait_for_load_balancer(lb.id)
        pool = conn.load_balancer.get_pool(pool.id)
        
        return lb, listener, pool


def register_server_with_lb(server, subnet_id):
        """Register server with load balancer if it already exists"""
        lb, _, pool = get_lb_resources()
        if not lb or not pool:
                return

        fixed_ip = get_fixed_ip(server)
        if not fixed_ip:
                return

        existing_addresses = {member.address for member in conn.load_balancer.members(pool.id)}
        if fixed_ip in existing_addresses:
                return

        conn.load_balancer.create_member(
                pool.id,
                address=fixed_ip,
                protocol_port=80,
                subnet_id=subnet_id
        )
        conn.load_balancer.wait_for_load_balancer(lb.id)


def unregister_server_from_lb(server):
        """Unregister server from load balancer"""
        lb, _, pool = get_lb_resources()
        if not lb or not pool:
                return

        fixed_ip = get_fixed_ip(server)
        if not fixed_ip:
                return

        for member in conn.load_balancer.members(pool.id):
                if member.address == fixed_ip:
                        conn.load_balancer.delete_member(member.id, pool.id, ignore_missing=True)
                        conn.load_balancer.wait_for_load_balancer(lb.id)
                        break


def sync_lb_members(subnet_id):
        """Synchronize members with load balancer"""
        lb, _, pool = ensure_load_balancer(subnet_id)
        existing_addresses = {member.address for member in conn.load_balancer.members(pool.id)}
        
        for srv in conn.compute.servers():
                server = conn.compute.get_server(srv.id)
                fixed_ip = get_fixed_ip(server)
                if fixed_ip and fixed_ip not in existing_addresses:
                        conn.load_balancer.create_member(
                                pool.id,
                                address=fixed_ip,
                                protocol_port=80,
                                subnet_id=subnet_id
                        )
                        conn.load_balancer.wait_for_load_balancer(lb.id)
                        existing_addresses.add(fixed_ip)


# ============================================================================
# FLASK ROUTES
# ============================================================================

@app.route('/')
def index():
        """Home page - display server list and infrastructure information"""
        servers = []
        for srv in conn.compute.servers():
                full = conn.compute.get_server(srv.id)
                servers.append(summarize_server(full))
        servers.sort(key=lambda item: item["name"])

        network = conn.network.find_network(NET_NAME)
        subnet = conn.network.find_subnet(SUBNET_NAME)
        router = conn.network.find_router(ROUTER_NAME)

        # Load balancer details
        lb_details = None
        lb = conn.load_balancer.find_load_balancer(LOAD_BALANCER_NAME)
        if lb:
                lb = conn.load_balancer.get_load_balancer(lb.id)
                listener = conn.load_balancer.find_listener(LISTENER_NAME)
                if listener:
                        listener = conn.load_balancer.get_listener(listener.id)
                pool = conn.load_balancer.find_pool(POOL_NAME)
                members = []
                if pool:
                        pool = conn.load_balancer.get_pool(pool.id)
                        for member in conn.load_balancer.members(pool.id):
                                members.append({
                                        "id": member.id,
                                        "address": member.address,
                                        "protocol_port": member.protocol_port,
                                        "weight": getattr(member, "weight", None),
                                        "backup": getattr(member, "backup", False),
                                        "operating_status": getattr(member, "operating_status", None),
                                        "provisioning_status": getattr(member, "provisioning_status", None),
                                        "admin_state_up": getattr(member, "admin_state_up", None)
                                })
                lb_details = {
                        "name": lb.name,
                        "vip_address": lb.vip_address,
                        "floating_ip": get_lb_floating_ip(lb),
                        "provisioning_status": getattr(lb, "provisioning_status", None),
                        "operating_status": getattr(lb, "operating_status", None),
                        "admin_state_up": getattr(lb, "admin_state_up", None),
                        "listener_port": listener.protocol_port if listener else None,
                        "pool_algorithm": pool.lb_algorithm if pool else None,
                        "members": members
                }

        return render_template(
                'index.html',
                servers=servers,
                network=network,
                subnet=subnet,
                router=router,
                lb_details=lb_details,
                ext_net=EXT_NET_NAME,
                default_user_data=DEFAULT_USERDATA
        )


@app.route('/init')
def init():
        """Initialize network infrastructure"""
        net = conn.network.find_network(NET_NAME)
        subnet = conn.network.find_subnet(SUBNET_NAME)
        router = conn.network.find_router(ROUTER_NAME)

        if net and subnet and router:
                flash("Network infrastructure already initialized.")
        else:
                create_network_infra()
                flash("Network infrastructure initialized.")
        return redirect(url_for('index'))


@app.route('/create_vm', methods=['POST'])
def create_vm_route():
        """Create new VM from form"""
        if len(list(conn.compute.servers())) >= MAX_INSTANCES:
                flash(f"Maximum of {MAX_INSTANCES} instances reached.")
                return redirect(url_for('index'))
        
        name = request.form['name']
        user_data = request.form.get('user_data', DEFAULT_USERDATA)
        try:
                create_vm(name, user_data_script=user_data)
                push_refresh()
        except RuntimeError as exc:
                flash(str(exc))
        except Exception as exc:
                flash(f"Failed to create instance: {exc}")
        return redirect(url_for('index'))


@app.route('/delete_vm/<vm_id>', methods=['POST'])
def delete_vm(vm_id):
        """Delete VM"""
        server = conn.compute.get_server(vm_id)
        if server and getattr(server, "id", None):
                try:
                        unregister_server_from_lb(server)
                except AttributeError:
                        pass

                fip = None
                try:
                        fip = detach_floating_ip(server)
                except AttributeError:
                        fip = None

                conn.compute.delete_server(server.id, ignore_missing=True)
                if fip and getattr(fip, "id", None):
                        conn.network.delete_ip(fip, ignore_missing=True)
        push_refresh()
        return redirect(url_for('index'))


@app.route('/scale_up')
def scale_up():
        """Scale up - add new VM"""
        if len(list(conn.compute.servers())) >= MAX_INSTANCES:
                flash(f"Maximum of {MAX_INSTANCES} instances reached.")
                return redirect(url_for('index'))

        net = conn.network.find_network(NET_NAME)
        subnet = conn.network.find_subnet(SUBNET_NAME)
        if not net or not subnet:
                flash("Network infrastructure is not initialized. Please initialize the network before scaling up.")
                return redirect(url_for('index'))
        
        existing = list(conn.compute.servers())
        new_name = f"{GROUP_NAME}_vm{len(existing)+1}"
        try:
                create_vm(new_name)
                push_refresh()
        except Exception as exc:
                flash(f"Failed to scale up: {exc}")
        return redirect(url_for('index'))


@app.route('/scale_down')
def scale_down():
        """Scale down - delete oldest VM"""
        candidates = [srv for srv in conn.compute.servers() if getattr(srv, "id", None)]
        candidates.sort(key=lambda s: getattr(s, "created_at", ""))
        if candidates:
                target = conn.compute.get_server(candidates[-1].id)
                if target and getattr(target, "id", None):
                        try:
                                unregister_server_from_lb(target)
                        except AttributeError:
                                pass

                        fip = None
                        try:
                                fip = detach_floating_ip(target)
                        except AttributeError:
                                fip = None

                        conn.compute.delete_server(target.id, ignore_missing=True)
                        if fip and getattr(fip, "id", None):
                                conn.network.delete_ip(fip, ignore_missing=True)
        push_refresh()
        return redirect(url_for('index'))


@app.route('/instances/<vm_id>/power', methods=['POST'])
def power_action(vm_id):
        """Start/stop VM"""
        action = request.form.get('action')
        server = conn.compute.get_server(vm_id)
        if not server:
                return '', 404
        
        if action == 'start':
                conn.compute.start_server(server)
        elif action == 'stop':
                conn.compute.stop_server(server)
        else:
                return '', 400
        
        push_refresh()
        return '', 204


@app.route('/api/servers')
def api_servers():
        """API endpoint - return server list as JSON"""
        data = []
        for srv in conn.compute.servers():
                full = conn.compute.get_server(srv.id)
                data.append(summarize_server(full))
        data.sort(key=lambda item: item["name"])
        return jsonify(data)


@app.route('/events')
def events():
        """SSE endpoint - send real-time events"""
        def event_stream():
                q = queue.Queue()
                subscriptions.add(q)
                try:
                        while True:
                                msg = q.get()
                                yield f"data: {msg}\n\n"
                except GeneratorExit:
                        subscriptions.discard(q)
        
        return app.response_class(event_stream(), mimetype='text/event-stream')


@app.route('/init_lb')
def init_lb():
        """Initialize load balancer and sync members"""
        subnet = conn.network.find_subnet(SUBNET_NAME)
        if not subnet:
                flash("Network infrastructure is not initialized. Please initialize the network before creating the load balancer.")
                return redirect(url_for('index'))

        lb_before, _, _ = get_lb_resources()
        try:
                sync_lb_members(subnet.id)
                if lb_before:
                        flash("Load balancer already initialized. Members synchronized.")
                else:
                        flash("Load balancer initialized.")
                push_refresh()
        except Exception as exc:
                flash(f"Failed to initialize load balancer: {exc}")
        return redirect(url_for('index'))


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
        app.run(host='0.0.0.0', port=5000)
