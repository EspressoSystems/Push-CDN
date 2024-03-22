# Create a self-signed root CA
openssl req -x509 -sha256 -nodes -subj "/C=US" -days 36500 -newkey rsa:2048 -keyout root-ca.key -out root-ca.crt