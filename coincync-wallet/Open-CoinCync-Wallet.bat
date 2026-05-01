@echo off
title CoinCync Wallet
cd /d "%~dp0"
if not exist "node_modules\" (
  echo Installing dependencies...
  call npm install
  if errorlevel 1 exit /b 1
)
echo Starting CoinCync Wallet (desktop)...
call npm run start
