#!/bin/bash
# Deploy Leash landing page to colo server
# Usage: ./scripts/deploy-site.sh
# Requires: SSH access to packetflood.org

set -e

REMOTE="ryan@packetflood.org"
PORT=999
REMOTE_PATH="/var/www/leash.meridianhouse.tech"

echo "🐕 Deploying Leash landing page..."

# Create remote directory
ssh -p $PORT $REMOTE "sudo mkdir -p $REMOTE_PATH && sudo chown ryan:ryan $REMOTE_PATH"

# Copy site files
scp -P $PORT -r site/* $REMOTE:$REMOTE_PATH/

# Set up Apache vhost (if not already configured)
ssh -p $PORT $REMOTE "
if [ ! -f /etc/apache2/sites-available/leash.meridianhouse.tech.conf ]; then
    sudo tee /etc/apache2/sites-available/leash.meridianhouse.tech.conf << 'EOF'
<VirtualHost *:80>
    ServerName leash.meridianhouse.tech
    DocumentRoot $REMOTE_PATH
    <Directory $REMOTE_PATH>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOF
    sudo a2ensite leash.meridianhouse.tech.conf
    sudo systemctl reload apache2
    echo 'Apache vhost created and enabled'
else
    echo 'Apache vhost already exists'
fi
"

echo "✅ Deployed to https://leash.meridianhouse.tech"
echo ""
echo "Next steps:"
echo "  1. Add DNS A record: leash.meridianhouse.tech → colo IP"
echo "  2. Run: sudo certbot --apache -d leash.meridianhouse.tech"
