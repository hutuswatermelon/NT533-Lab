CÁC BƯỚC TRIỂN KHAI
Lưu ý: Đổi file clouds.yaml và openrc.sh bằng file của bản thân
1. Cấp quyền thực thi:
    chmod +x presetup.sh
2. Chạy setup:
    ./presetup.sh
3. Kích hoạt môi trường ảo và chạy app:
    source venv/bin/activate
    source ~/openstack_app/NT533.Q13-TH1.02-openrc.sh
    python3 app.py