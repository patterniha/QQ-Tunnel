#!/usr/bin/env bash

openssl req -x509 -nodes -days 3650 \
  -newkey rsa:2048 \
  -keyout www-google-com.key \
  -out www-google-com.crt \
  -subj "/CN=www.google.com" \
  -addext "subjectAltName=DNS:www.google.com"
  