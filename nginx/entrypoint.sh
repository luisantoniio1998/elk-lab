#!/bin/sh

# Remove symlinks created by Alpine Nginx
rm -f /var/log/nginx/access.log /var/log/nginx/error.log

# Create actual log files
touch /var/log/nginx/access.log /var/log/nginx/error.log

# Start Nginx
exec nginx -g 'daemon off;'
