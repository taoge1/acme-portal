@echo off
REM Windows 下打包为 exe
REM 前提：已安装 Python + pyinstaller
REM 用法：双击运行

pip install pyinstaller flask cryptography acme josepy requests

pyinstaller --onefile ^
  --name "ACME证书管理" ^
  --add-data "templates;templates" ^
  --add-data "state;state" ^
  --hidden-import flask ^
  --hidden-import cryptography ^
  --hidden-import acme ^
  --hidden-import acme.client ^
  --hidden-import acme.messages ^
  --hidden-import acme.challenges ^
  --hidden-import acme.crypto_util ^
  --hidden-import acme.errors ^
  --hidden-import josepy ^
  --hidden-import requests ^
  --hidden-import smtplib ^
  --hidden-import sqlite3 ^
  --hidden-import zipfile ^
  --hidden-import email.mime.text ^
  --hidden-import email.mime.multipart ^
  --hidden-import email.mime.base ^
  --hidden-import email.encoders ^
  acme_portal.py

echo.
echo 打包完成！exe 文件在 dist\ACME证书管理.exe
echo 双击运行后，浏览器打开 http://localhost:10501
pause
