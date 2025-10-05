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

# --- Kết nối đến OpenStack ---
print("Connecting to OpenStack")
username = os.getenv("OS_USERNAME")
print(f"Username: {username}")
password = getpass.getpass("Enter your OpenStack password: ")
conn = openstack.connect(cloud='openstack',
			 password=password)

# --- Cấu hình cố định ---
GROUP_NAME = "nhom02"
NET_NAME = f"{GROUP_NAME}_net"
SUBNET_NAME = f"{GROUP_NAME}_subnet"
ROUTER_NAME = f"{GROUP_NAME}_router"
CIDR = "192.168.2.0/24"
IMAGE_NAME = "Ubuntu 22.04"
FLAVOR_NAME = "d10.xs1"
KEYPAIR_NAME = "Nhom02Key"
EXT_NET_NAME = "Public_Net"
DNS_NAMESERVERS = [
    "8.8.8.8",
    "1.1.1.1"
]

LOAD_BALANCER_NAME = f"{GROUP_NAME}_lb"
LISTENER_NAME = f"{GROUP_NAME}_listener"
POOL_NAME = f"{GROUP_NAME}_pool"
HEALTH_MONITOR_NAME = f"{GROUP_NAME}_hm"

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

def encode_user_data(script_text: str) -> str:
    return base64.b64encode(script_text.encode("utf-8")).decode("utf-8")

# --- Hàm tạo hạ tầng ---
def create_network_infra():
    net = conn.network.find_network(NET_NAME)
    if not net:
        net = conn.network.create_network(
            name=NET_NAME,
            port_security_enabled=False
        )
    else:
        if getattr(net, "port_security_enabled", True):
            net = conn.network.update_network(net, port_security_enabled=False)
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

# --- Hàm tạo VM ---
def allocate_floating_ip(server):
    ext_net = conn.network.find_network(EXT_NET_NAME)
    if not ext_net:
        raise RuntimeError(f"External network '{EXT_NET_NAME}' not found.")
    ports = list(conn.network.ports(device_id=server.id))
    if not ports:
        raise RuntimeError(f"No port found for server {server.name}.")

    reusable_fip = None
    for ip in conn.network.ips():
        if (
            getattr(ip, "floating_network_id", None) == ext_net.id
            and getattr(ip, "port_id", None) is None
        ):
            reusable_fip = ip
            break

    if reusable_fip:
        conn.network.update_ip(reusable_fip, port_id=ports[0].id)
        return conn.network.get_ip(reusable_fip.id)

    fip = conn.network.create_ip(floating_network_id=ext_net.id)
    conn.network.update_ip(fip, port_id=ports[0].id)
    return conn.network.get_ip(fip.id)

def create_vm(name, user_data_script=None):
    net, subnet, _ = create_network_infra()
    image = conn.compute.find_image(IMAGE_NAME, ignore_missing=True)
    if not image:
        raise RuntimeError(f"Image '{IMAGE_NAME}' not found.")
    flavor = conn.compute.find_flavor(FLAVOR_NAME, ignore_missing=True)
    if not flavor:
        raise RuntimeError(f"Flavor '{FLAVOR_NAME}' not found.")
    keypair = conn.compute.find_keypair(KEYPAIR_NAME)
    if not keypair:
        raise RuntimeError(f"Keypair '{KEYPAIR_NAME}' not found.")
    script = (user_data_script or DEFAULT_USERDATA).strip() or DEFAULT_USERDATA
    port = conn.network.create_port(
        name=f"{name}_port",
        network_id=net.id,
        port_security_enabled=False
    )
    try:
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
    fip = allocate_floating_ip(server)
    server = conn.compute.get_server(server.id)
    # register_server_with_lb(server, subnet.id)  # Tạm thời vô hiệu hóa LB
    return server, fip.floating_ip_address

def get_fixed_ip(server):
    for addr_list in (server.addresses or {}).values():
        for addr in addr_list:
            if addr.get("OS-EXT-IPS:type") == "fixed":
                return addr.get("addr")
    return None


def get_floating_ip(server):
    for addr_list in (server.addresses or {}).values():
        for addr in addr_list:
            if addr.get("OS-EXT-IPS:type") == "floating":
                return addr.get("addr")
    return None


STATUS_LABEL = {
    "BUILD": "Provisioning",
    "ACTIVE": "Active",
    "ERROR": "Error"
}
TASK_LABEL = {
    "spawning": "Provisioning",
    "networking": "Configuring network",
    "configuring": "Running user data"
}

def readable_status(server):
    task = getattr(server, "OS-EXT-STS:task_state", None)
    if task and task in TASK_LABEL:
        return TASK_LABEL[task]
    return STATUS_LABEL.get(server.status, server.status)

def summarize_server(server):
    return {
        "id": server.id,
        "name": server.name,
        "status": server.status,
        "display_status": readable_status(server),
        "fixed_ip": get_fixed_ip(server),
        "floating_ip": get_floating_ip(server)
    }

# --- Flask Routes ---
@app.route('/')
def index():
    servers = []
    for srv in conn.compute.servers():
        full = conn.compute.get_server(srv.id)
        servers.append(summarize_server(full))
    servers.sort(key=lambda item: item["name"])

    network = conn.network.find_network(NET_NAME)
    subnet = conn.network.find_subnet(SUBNET_NAME)
    router = conn.network.find_router(ROUTER_NAME)

    lb_details = None
    # lb = conn.load_balancer.find_load_balancer(LOAD_BALANCER_NAME)
    # if lb:
    #     lb = conn.load_balancer.get_load_balancer(lb.id)
    #     listener = conn.load_balancer.find_listener(LISTENER_NAME)
    #     if listener:
    #         listener = conn.load_balancer.get_listener(listener.id)
    #     pool = conn.load_balancer.find_pool(POOL_NAME)
    #     members = []
    #     if pool:
    #         pool = conn.load_balancer.get_pool(pool.id)
    #         for member in conn.load_balancer.members(pool.id):
    #             members.append({
    #                 "id": member.id,
    #                 "address": member.address,
    #                 "protocol_port": member.protocol_port,
    #                 "operating_status": member.operating_status
    #             })
    #     lb_details = {
    #         "name": lb.name,
    #         "vip_address": lb.vip_address,
    #         "provisioning_status": lb.provisioning_status,
    #         "operating_status": getattr(lb, "operating_status", None),
    #         "listener_port": listener.protocol_port if listener else None,
    #         "pool_algorithm": pool.lb_algorithm if pool else None,
    #         "members": members
    #     }

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
    create_network_infra()
    return redirect(url_for('index'))

MAX_INSTANCES = 5

@app.route('/create_vm', methods=['POST'])
def create_vm_route():
    if len(list(conn.compute.servers())) >= MAX_INSTANCES:
        flash(f"Maximum of {MAX_INSTANCES} instances reached.")
        return redirect(url_for('index'))
    name = request.form['name']
    user_data = request.form.get('user_data', DEFAULT_USERDATA)
    create_vm(name, user_data_script=user_data)
    push_refresh()
    return redirect(url_for('index'))

@app.route('/delete_vm/<vm_id>', methods=['POST'])
def delete_vm(vm_id):
    server = conn.compute.get_server(vm_id)
    if server:
        fip = detach_floating_ip(server)
        conn.compute.delete_server(vm_id, ignore_missing=True)
        if fip:
            conn.network.delete_ip(fip, ignore_missing=True)
    push_refresh()
    return redirect(url_for('index'))

@app.route('/scale_up')
def scale_up():
    if len(list(conn.compute.servers())) >= MAX_INSTANCES:
        flash(f"Maximum of {MAX_INSTANCES} instances reached.")
        return redirect(url_for('index'))
    create_network_infra()
    existing = list(conn.compute.servers())
    new_name = f"{GROUP_NAME}_vm{len(existing)+1}"
    create_vm(new_name)
    push_refresh()
    return redirect(url_for('index'))

@app.route('/scale_down')
def scale_down():
    servers = sorted(conn.compute.servers(), key=lambda s: getattr(s, "created_at", ""))
    if servers:
        target = conn.compute.get_server(servers[-1].id)
        # unregister_server_from_lb(target)  # Tạm thời vô hiệu hóa LB
        fip = detach_floating_ip(target)
        conn.compute.delete_server(target.id, ignore_missing=True)
        if fip:
            conn.network.delete_ip(fip, ignore_missing=True)
    push_refresh()
    return redirect(url_for('index'))

# @app.route('/init_lb')
# def init_lb():
#     _, subnet, _ = create_network_infra()
#     if subnet:
#         sync_lb_members(subnet.id)
#     return redirect(url_for('index'))


def detach_floating_ip(server):
    floating_ip = get_floating_ip(server)
    if not floating_ip:
        return None
    fip = conn.network.find_ip(floating_ip, ignore_missing=True)
    if not fip:
        return None
    if getattr(fip, "port_id", None):
        conn.network.update_ip(fip, port_id=None)
    return fip


def ensure_load_balancer(subnet_id):
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
    lb, _, pool = ensure_load_balancer(subnet_id)
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
    conn.load_balancer.wait_for_load_balancer(lb)


def unregister_server_from_lb(server):
    lb = conn.load_balancer.find_load_balancer(LOAD_BALANCER_NAME)
    pool = conn.load_balancer.find_pool(POOL_NAME)
    if not lb or not pool:
        return
    pool = conn.load_balancer.get_pool(pool.id)
    fixed_ip = get_fixed_ip(server)
    if not fixed_ip:
        return
    for member in conn.load_balancer.members(pool.id):
        if member.address == fixed_ip:
            conn.load_balancer.delete_member(member.id, pool.id, ignore_missing=True)
            conn.load_balancer.wait_for_load_balancer(lb)
            break


def sync_lb_members(subnet_id):
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
            conn.load_balancer.wait_for_load_balancer(lb)
            existing_addresses.add(fixed_ip)


@app.route('/api/servers')
def api_servers():
    data = []
    for srv in conn.compute.servers():
        full = conn.compute.get_server(srv.id)
        data.append(summarize_server(full))
    data.sort(key=lambda item: item["name"])
    return jsonify(data)


subscriptions = set()

event_queue = queue.Queue()

def push_refresh():
    for q in list(subscriptions):
        q.put("refresh")


def event_stream():
    q = queue.Queue()
    subscriptions.add(q)
    try:
        while True:
            msg = q.get()
            yield f"data: {msg}\n\n"
    except GeneratorExit:
        subscriptions.discard(q)


@app.route('/events')
def events():
    return app.response_class(event_stream(), mimetype='text/event-stream')


@app.route('/instances/<vm_id>/power', methods=['POST'])
def power_action(vm_id):
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


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
