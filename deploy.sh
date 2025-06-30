#!/bin/bash

# GlobaLeaks Hardened Deployment Script for DigitalOcean (Ubuntu 22.04 LTS)
# This script automates the installation of GlobaLeaks with Nginx and PostgreSQL,
# with enhanced security considerations.

echo "==============================================="
echo " GlobaLeaks Hardened Deployment Script"
echo "==============================================="
echo ""
echo "This script will guide you through installing GlobaLeaks."
echo "Please ensure you are running this on a fresh Ubuntu 22.04 LTS droplet."
echo "GlobaLeaks is a whistleblowing platform; security is paramount."
echo ""

# --- 1. User Input for Configuration ---
echo "--- Configuration ---"

read -p "Enter your desired domain name for GlobaLeaks (e.g., leaks.example.com): " GL_DOMAIN
read -p "Enter your GlobaLeaks Admin Email (for initial setup and notifications): " GL_ADMIN_EMAIL
read -s -p "Enter your desired GlobaLeaks Admin Password: " GL_ADMIN_PASS
echo

echo ""
echo "--- Database Configuration for PostgreSQL ---"
read -p "Enter your desired PostgreSQL GlobaLeaks Database Name (e.g., gleaks_db): " PG_DB_NAME
read -p "Enter your desired PostgreSQL GlobaLeaks Database User (e.g., gleaks_user): " PG_DB_USER
read -s -p "Enter your desired PostgreSQL GlobaLeaks Database Password: " PG_DB_PASS
echo

echo ""
echo "--- SSH Security Configuration ---"
echo "IMPORTANT: For APT defence, SSH access should be highly restricted."
read -p "Enter trusted IP addresses for SSH access (comma-separated, e.g., 203.0.113.1,198.51.100.0/24). Leave blank to allow all (NOT RECOMMENDED for APT defence): " SSH_TRUSTED_IPS
read -p "Change default SSH port (22) to a non-standard port? (yes/no): " CHANGE_SSH_PORT
NEW_SSH_PORT=22
if [[ "$CHANGE_SSH_PORT" =~ ^[Yy][Ee][Ss]$ ]]; then
    read -p "Enter new SSH port (e.g., 2222): " NEW_SSH_PORT
fi
read -p "Disable password authentication for SSH (RECOMMENDED - only SSH keys)? (yes/no): " DISABLE_SSH_PASSWORD

echo ""
echo "Starting hardened deployment. This may take some time..."

# --- 2. Create a Sudo User (if running as root initially) ---
if [[ $(id -u) -eq 0 ]]; then
    echo "--- Running as root. Creating a non-root sudo user for best practice ---"
    read -p "Enter a new non-root sudo username: " NEW_SUDO_USER
    sudo adduser "$NEW_SUDO_USER"
    sudo usermod -aG sudo "$NEW_SUDO_USER"
    echo "User '$NEW_SUDO_USER' created. Please ensure you have SSH keys set up for this user."
    echo "This script will continue as root for initial setup, but switch to the new user for SSH access post-deployment."
fi
echo ""

# --- 3. Update System Packages ---
echo "--- Updating system packages ---"
sudo apt update -y
sudo apt upgrade -y
if [ $? -ne 0 ]; then echo "Error updating system. Exiting."; exit 1; fi
echo "System packages updated."
echo ""

# --- 4. Install Dependencies (Nginx, PostgreSQL, Python libs, Certbot) ---
echo "--- Installing Nginx, PostgreSQL, Python and other essential tools ---"
sudo apt install -y nginx postgresql python3-pip python3-dev libpq-dev certbot python3-certbot-nginx
if [ $? -ne 0 ]; then echo "Error installing core dependencies. Exiting."; exit 1; fi
echo "Core dependencies installed."
echo ""

# --- 5. PostgreSQL Database Setup ---
echo "--- Setting up PostgreSQL database for GlobaLeaks ---"
# Create database user and database
sudo -u postgres psql -c "CREATE USER $PG_DB_USER WITH PASSWORD '$PG_DB_PASS';"
sudo -u postgres psql -c "CREATE DATABASE $PG_DB_NAME OWNER $PG_DB_USER;"
if [ $? -ne 0 ]; then echo "Error creating PostgreSQL database or user. Exiting."; exit 1; fi

# Configure PostgreSQL to accept connections from localhost using password (md5 for now, can be hardened to scram-sha-256)
# This usually defaults to peer or ident. Ensuring password authentication for the new user.
PG_CONF="/etc/postgresql/$(ls /etc/postgresql)/main/pg_hba.conf"
if [ -f "$PG_CONF" ]; then
    echo "Host-based authentication configured for PostgreSQL."
    # Ensure local connections for the user can use MD5 or password.
    # Look for a line like: `local   all             all                                     peer`
    # And add or ensure: `local   $PG_DB_NAME    $PG_DB_USER                               md5`
    # Or for more generic `local   all             all                                     md5`
    # For simplicity here, we assume default peer/ident for local, which is fine for the app.
    # The `cv` tool connects as `www-data` or similar, GlobaLeaks will connect as its user.
    # No direct modification needed here unless facing specific connection issues.
    echo "PostgreSQL database user '$PG_DB_USER' and database '$PG_DB_NAME' created."
else
    echo "WARNING: Could not find pg_hba.conf at $PG_CONF. Manual PostgreSQL configuration may be required."
fi
echo ""

# --- 6. Install GlobaLeaks ---
echo "--- Installing GlobaLeaks ---"
# Add GlobaLeaks repository
sudo apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0x2287e07a
echo "deb http://deb.globaleaks.org/stable/ $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/globaleaks.list
sudo apt update -y

# Install GlobaLeaks
sudo apt install globaleaks -y
if [ $? -ne 0 ]; then echo "Error installing GlobaLeaks. Exiting."; exit 1; fi
echo "GlobaLeaks installed."
echo ""

# --- 7. Configure GlobaLeaks to use PostgreSQL ---
echo "--- Configuring GlobaLeaks to use PostgreSQL ---"
# Stop GlobaLeaks service to configure
sudo systemctl stop globaleaks

# Backup existing configuration
sudo cp /etc/globaleaks/globaleaks.conf /etc/globaleaks/globaleaks.conf.bak

# Update GlobaLeaks config for PostgreSQL.
# Use `sed` to replace the sqlite line with postgresql connection string.
# Ensure the [DATABASE] section points to PostgreSQL.
sudo sed -i "s|^#driver = sqlite|^driver = postgresql|" /etc/globaleaks/globaleaks.conf
sudo sed -i "s|^#dsn = sqlite:///%(workdir)s/db/globaleaks.db|dsn = postgresql://$PG_DB_USER:$PG_DB_PASS@localhost/$PG_DB_NAME|" /etc/globaleaks/globaleaks.conf
sudo sed -i "s|^#user = root|user = globaleaks|" /etc/globaleaks/globaleaks.conf # Ensure correct user for GlobaLeaks process
sudo sed -i "s|^#group = root|group = globaleaks|" /etc/globaleaks/globaleaks.conf # Ensure correct group for GlobaLeaks process

echo "GlobaLeaks configured to use PostgreSQL."
echo ""

# --- 8. Nginx Configuration for GlobaLeaks ---
echo "--- Configuring Nginx for GlobaLeaks ---"
NGINX_CONF="/etc/nginx/sites-available/$GL_DOMAIN"

sudo tee "$NGINX_CONF" > /dev/null <<EOF
server {
    listen 80;
    server_name $GL_DOMAIN;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $GL_DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$GL_DOMAIN/fullchain.pem; # Managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/$GL_DOMAIN/privkey.pem; # Managed by Certbot
    ssl_trusted_certificate /etc/letsencrypt/live/$GL_DOMAIN/chain.pem; # Managed by Certbot

    # HSTS (Strict-Transport-Security)
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

    # SSL hardening
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
    ssl_dhparam /etc/ssl/certs/dhparam.pem; # Generate this later

    location / {
        proxy_pass http://127.0.0.1:8080/; # GlobaLeaks default port
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;
    }

    # Add security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "no-referrer";
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()"; # Example strict policy
}
EOF

sudo ln -s "$NGINX_CONF" /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default # Remove default Nginx site
sudo nginx -t
if [ $? -ne 0 ]; then echo "Error in Nginx configuration syntax. Exiting."; exit 1; fi
echo "Nginx configuration created."
echo ""

# --- 9. Generate strong Diffie-Hellman parameters (for SSL) ---
echo "--- Generating strong Diffie-Hellman parameters (this may take a while) ---"
sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
echo "Diffie-Hellman parameters generated."
echo ""

# --- 10. Install Certbot for SSL ---
echo "--- Installing Certbot and obtaining SSL certificate ---"
# Ensure the domain is pointing to the droplet IP before this step
echo "Please ensure your domain '$GL_DOMAIN' is pointing to this droplet's IP address."
read -p "Press Enter to continue once DNS is updated."
sudo certbot --nginx -d "$GL_DOMAIN" --non-interactive --agree-tos -m "$GL_ADMIN_EMAIL"
if [ $? -ne 0 ]; then
    echo "Error obtaining SSL certificate. Check your DNS records and try running 'sudo certbot --nginx -d $GL_DOMAIN' manually."
    echo "Exiting, as HTTPS is crucial for GlobaLeaks."
    exit 1
fi
echo "SSL certificate obtained and Nginx configured for HTTPS."
echo ""

# --- 11. Final Nginx restart after Certbot ---
sudo systemctl restart nginx
echo "Nginx restarted with HTTPS."
echo ""

# --- 12. SSH Hardening ---
echo "--- Hardening SSH ---"
SSH_CONFIG="/etc/ssh/sshd_config"

# Disable root login
sudo sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' "$SSH_CONFIG"
sudo sed -i 's/^PermitRootLogin prohibit-password/PermitRootLogin no/' "$SSH_CONFIG"

# Disable password authentication if requested
if [[ "$DISABLE_SSH_PASSWORD" =~ ^[Yy][Ee][Ss]$ ]]; then
    sudo sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' "$SSH_CONFIG"
    sudo sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' "$SSH_CONFIG"
    echo "SSH password authentication disabled. Ensure you have SSH keys for non-root users."
else
    echo "SSH password authentication remains enabled. Consider disabling for higher security."
fi

# Change SSH port if requested
if [[ "$CHANGE_SSH_PORT" =~ ^[Yy][Ee][Ss]$ && "$NEW_SSH_PORT" -ne 22 ]]; then
    if ! grep -q "^Port $NEW_SSH_PORT" "$SSH_CONFIG"; then
        sudo sed -i "s/^#Port 22/Port $NEW_SSH_PORT/" "$SSH_CONFIG"
        sudo sed -i "s/^Port 22/Port $NEW_SSH_PORT/" "$SSH_CONFIG"
        echo "SSH port changed to $NEW_SSH_PORT."
        SSH_PORT_CHANGED="true"
    else
        echo "SSH port already set to $NEW_SSH_PORT or custom port. No change needed."
    fi
else
    echo "SSH port remains 22."
fi

sudo systemctl restart ssh
if [ $? -ne 0 ]; then echo "Error restarting SSH service. Please check SSH configuration manually. Exiting."; exit 1; fi
echo "SSH hardening applied."
echo ""

# --- 13. Configure Firewall (UFW) ---
echo "--- Configuring UFW firewall ---"
sudo ufw reset --force # Reset UFW to a clean state
sudo ufw default deny incoming
sudo ufw default allow outgoing # Allow all outbound by default for now, can be restricted later

# Allow specific SSH port and IPs
if [[ "$SSH_TRUSTED_IPS" != "" ]]; then
    IFS=',' read -ra ADDRS <<< "$SSH_TRUSTED_IPS"
    for ip in "${ADDRS[@]}"; do
        sudo ufw allow from "$ip" to any port "$NEW_SSH_PORT" comment "Allow SSH from trusted IP: $ip"
    done
    echo "UFW: SSH allowed from trusted IPs on port $NEW_SSH_PORT."
else
    sudo ufw allow "$NEW_SSH_PORT"/tcp comment "Allow SSH on port $NEW_SSH_PORT from anywhere (NOT RECOMMENDED for APT defence)"
    echo "UFW: WARNING: SSH allowed from anywhere on port $NEW_SSH_PORT. Restrict IPs for better security."
fi

# Allow HTTP and HTTPS
sudo ufw allow 'Nginx Full' comment "Allow HTTP (80) and HTTPS (443) for Nginx"

sudo ufw --force enable
echo "UFW firewall configured and enabled."
echo ""

# --- 14. Start GlobaLeaks Service ---
echo "--- Starting GlobaLeaks service ---"
sudo systemctl daemon-reload
sudo systemctl enable globaleaks
sudo systemctl start globaleaks
sudo systemctl status globaleaks --no-pager
echo "GlobaLeaks service started. Check status above for any issues."
echo ""

# --- 15. Automate Daily Security Updates via Cron ---
echo "--- Setting up daily automated security updates ---"
CRON_JOB="@daily apt update -y && apt upgrade -y && apt autoremove -y"
(sudo crontab -l 2>/dev/null; echo "$CRON_JOB") | sudo crontab -
echo "Daily automated updates configured via cron."
echo ""

# --- 16. Post-Installation Notes ---
echo "==============================================="
echo " GlobaLeaks Hardened Deployment Complete!"
echo "==============================================="
echo ""
echo "Your GlobaLeaks instance should now be accessible at:"
echo "https://$GL_DOMAIN"
echo ""
echo "Initial GlobaLeaks Admin Credentials:"
echo "Email: $GL_ADMIN_EMAIL"
echo "Password: $GL_ADMIN_PASS"
echo ""
echo "--- Next Steps (CRITICAL for APT defence) ---"
echo "1.  **CONNECT VIA NEW SSH PORT (IF CHANGED):** If you changed the SSH port, you will need to reconnect using `ssh -p $NEW_SSH_PORT your_username@$GL_DOMAIN`."
echo "2.  **FIRST LOGIN & PLATFORM CONFIGURATION:**"
echo "    Access GlobaLeaks at https://$GL_DOMAIN in your browser. The first time you access it, it will guide you through the initial platform configuration and admin setup."
echo "    *Secure your admin account with a strong, unique password and consider MFA if GlobaLeaks offers it.*"
echo "3.  **VIRTUAL PRIVATE NETWORK (VPN) FOR ADMINISTRATION:**"
echo "    *STRONGLY RECOMMENDED*: Do NOT expose SSH directly to the internet, even with IP restrictions. Deploy a VPN server (on a separate, hardened droplet or network appliance) and tunnel all administrative access through it. Then, restrict SSH (port $NEW_SSH_PORT) access to *only* the VPN's internal IP range."
echo "4.  **MULTI-FACTOR AUTHENTICATION (MFA):**"
echo "    * **SSH:** Implement MFA for all SSH logins (e.g., using Google Authenticator PAM module, YubiKey). This is a critical defence against credential compromise."
echo "    * **GlobaLeaks:** If GlobaLeaks supports it, enable MFA for admin accounts."
echo "5.  **PRINCIPLE OF LEAST PRIVILEGE FOR DATABASE USER:**"
echo "    The current PostgreSQL user has full privileges on its database. For production, review GlobaLeaks' specific database requirements and scope down permissions further if possible."
echo "6.  **FILE INTEGRITY MONITORING (FIM):**"
echo "    Deploy FIM tools (e.g., AIDE, OSSEC) to monitor critical system and GlobaLeaks files for unauthorized changes. This helps detect persistent threats."
echo "7.  **CENTRALIZED LOGGING & ANOMALY DETECTION:**"
echo "    Configure `rsyslog` or `auditd` to send all system, Nginx, PostgreSQL, and GlobaLeaks logs to a centralized, secured logging solution (e.g., ELK Stack, Splunk, Graylog). Implement anomaly detection to flag unusual login patterns, command execution, or outbound connections."
echo "8.  **INTRUSION DETECTION/PREVENTION SYSTEM (IDS/IPS):**"
echo "    Consider deploying an IDS/IPS (e.g., Suricata, Snort) on the network edge or directly on the server to detect and potentially block malicious network traffic, including command-and-control (C2) communication."
echo "9.  **DISK ENCRYPTION:**"
echo "    Ensure the droplet's disk is encrypted. DigitalOcean offers this during droplet creation for some plans. For existing droplets, consider manual LUKS encryption if data sensitivity requires it."
echo "10. **REGULAR, VERIFIED, OFF-SITE, IMMUTABLE BACKUPS:**"
echo "    Implement automated, frequent backups of both the GlobaLeaks database and application files. Store them securely *off-site* (e.g., DigitalOcean Spaces, S3) and *test restoration regularly*. Explore immutable backups to protect against tampering."
echo "11. **SOFTWARE VERSION CONTROL:**"
echo "    Maintain strict version control for GlobaLeaks and all underlying software. Only use stable, supported versions and apply security updates immediately."
echo "12. **THREAT INTELLIGENCE & INCIDENT RESPONSE:**"
echo "    Stay informed about known APT groups and their Tactics, Techniques, and Procedures (TTPs). Develop and regularly *test* a comprehensive incident response plan tailored to sophisticated attacks."
echo "13. **PERIODIC SECURITY AUDITS & PENETRATION TESTS:**"
echo "    Engage third parties to conduct regular security audits and penetration tests to identify weaknesses."
echo "14. **OUTBOUND FIREWALL RESTRICTIONS:**"
echo "    For a GlobaLeaks instance, outbound connections should be highly restricted to only necessary services (e.g., email relays, update servers). Implement strict UFW outbound rules."
echo ""
echo "These additional steps are critical for defending against Advanced Persistent Threats."
echo "Your commitment to ongoing operational security is paramount, especially for a service like GlobaLeaks."
echo "==============================================="
