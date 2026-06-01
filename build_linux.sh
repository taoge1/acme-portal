#!/bin/bash
# 在 Linux 下打包为可执行文件（适用于 Linux/Mac 用户）
# Windows 用户请用 build_windows.bat

pyinstaller --onefile \
  --name "acme-portal" \
  --add-data "templates:templates" \
  --add-data "state:state" \
  --hidden-import flask \
  --hidden-import cryptography \
  --hidden-import acme \
  --hidden-import acme.client \
  --hidden-import acme.messages \
  --hidden-import acme.challenges \
  --hidden-import acme.crypto_util \
  --hidden-import acme.errors \
  --hidden-import josepy \
  --hidden-import requests \
  --hidden-import smtplib \
  --hidden-import sqlite3 \
  --hidden-import zipfile \
  --hidden-import email.mime.text \
  --hidden-import email.mime.multipart \
  --hidden-import email.mime.base \
  --hidden-import email.encoders \
  acme_portal.py

echo ""
echo "打包完成！可执行文件在 dist/acme-portal"
echo "运行方式：./dist/acme-portal"
echo "浏览器打开：http://localhost:10501"
