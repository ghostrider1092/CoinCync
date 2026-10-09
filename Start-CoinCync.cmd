@echo off
rem ============================================================
rem   CoinCync - easy launcher.  Just double-click this file.
rem   Pick a number to run a node, mine, or make a wallet.
rem ============================================================
set "PS=%~dp0scripts\start-coincync.ps1"
if not exist "%PS%" set "PS=%~dp0start-coincync.ps1"
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS%" %*
