# Project Setup Guide

## 1. Generate Admin Key  
Create asymmetric key with passphrase using OpenSSL:  
```bash
openssl genrsa -aes256 -out admin.pem 2048
openssl rsa -in admin.pem -pubout -out configs/admin.pub
```

- `admin.pem` → private key (keep secure)  
- `configs/admin.pub` → public key used for initial setup  

---

## 2. Create IPNS Keys  
Make folder in root of project:  
```bash
mkdir ipns_keys
```

On your admin system, create IPNS keys:  
```bash
ipfs key gen --type=ed25519 access_control
ipfs key gen --type=ed25519 logs
ipfs key gen --type=ed25519 misc
ipfs key gen --type=ed25519 project_builds
ipfs key gen --type=ed25519 projects
ipfs key gen --type=ed25519 roles
ipfs key gen --type=ed25519 user_publickey
```

Export each key:  
```bash
ipfs key export access_control --output access_control.key
ipfs key export logs --output logs.key
ipfs key export misc --output misc.key
ipfs key export project_builds --output project_builds.key
ipfs key export projects --output projects.key
ipfs key export roles --output roles.key
ipfs key export user_publickey --output user_publickey.key
```

Move all `.key` files into `ipns_keys` folder and put it in folder of project root.  

---

## 3. Prepare Docker Compose  
Create a file `docker-compose.yml` in the root with the following content:

```yaml
version: '3.8'

x-build-args: &build-args
  APP_USERNAME: guest
  PASSWORD: "Guest@123"
  CLUSTER_SECRET: 
  ADMIN_PASSWORD: Admin@123
  SWARM_KEY: 

services:
  node1:
    build:
      context: .
      args: *build-args
    container_name: node1
    hostname: node1
    networks:
      ipfsnet:
        ipv4_address: 172.18.0.11
    ports:
      - "2221:22"
    volumes:
      - node1_home:/home/guest

  node2:
    build:
      context: .
      args: *build-args
    container_name: node2
    hostname: node2
    networks:
      ipfsnet:
        ipv4_address: 172.18.0.12
    ports:
      - "2222:22"
    volumes:
      - node2_home:/home/guest

  node3:
    build:
      context: .
      args: *build-args
    container_name: node3
    hostname: node3
    networks:
      ipfsnet:
        ipv4_address: 172.18.0.13
    ports:
      - "2223:22"
    volumes:
      - node3_home:/home/guest

networks:
  ipfsnet:
    driver: bridge
    ipam:
      config:
        - subnet: 172.18.0.0/16

volumes:
  node1_home:
  node2_home:
  node3_home:
```

---

## 4. Generate Secrets  
Create swarm key:  
```bash
echo -e "$(openssl rand -hex 32)"
```

Paste the value into `SWARM_KEY` in `docker-compose.yml`.  

Create cluster secret:  
```bash
openssl rand -hex 32
```

Paste the value into `CLUSTER_SECRET` in `docker-compose.yml`.  

---

## 5. Start Nodes  
Run the command in the project root:  
```bash
docker-compose up -d --build
```

Nodes will be created.  

---

## 6. Access Application Artefact  
Login to the container using SSH with private key and port forwarding:  
```bash
ssh -i <pvtkeylocation> -p <node_port> -L <local_port>:<host_ip_or_localhost>:<app_port> guest@<host_ip_or_localhost>
```

Replace placeholders:  
- `<pvtkeylocation>` → path to your private key  
- `<node_port>` → node port (e.g., 2221, 2222, 2223)  
- `<local_port>` → local port you want to forward  
- `<app_port>` → application port inside container  
- `<host_ip_or_localhost>` → host machine IP or `localhost`  

---

Setup is complete.  
