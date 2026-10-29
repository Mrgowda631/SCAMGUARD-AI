@echo off
title SCAMGUARD AI - Security Operations Center
cd /d "%~dp0"

echo ============================================================
echo   SCAMGUARD AI - Social Media Scam Detection System
echo ============================================================
echo   Backend Port : 8000 (API ^& Threat Engine)
echo   Frontend Port: 8080 (Vite SOC Dashboard)
echo   Dashboard URL: http://localhost:8080
echo ============================================================
echo.

:: 1. Verify Node.js is installed
where node >nul 2>nul
if %errorlevel% neq 0 (
  echo [ERROR] Node.js is not installed or not in your system PATH.
  echo Please install Node.js from https://nodejs.org/ and restart this script.
  echo.
  pause
  exit /b 1
)

:: 2. Check if node_modules exists, install dependencies if missing
if not exist "node_modules\" (
  echo [*] Project dependencies missing. Running 'npm install'...
  call npm install
  if %errorlevel% neq 0 (
    echo [ERROR] Failed to install project dependencies.
    pause
    exit /b 1
  )
)

:: 3. Safely free ports (8080, 8000, 5173, 3000) if occupied by orphaned node or python processes
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ports = @(8080, 8000, 5173, 3000); foreach ($p in $ports) { $conns = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue; foreach ($conn in $conns) { $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue; if ($proc -and ($proc.ProcessName -like '*node*' -or $proc.ProcessName -like '*python*')) { Write-Host \"[*] Releasing port $p used by previous orphaned $($proc.ProcessName) ($($proc.Id))...\"; Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } } }"

:: 4. Build client assets if missing
if not exist "client\dist\" (
  echo [*] Building client production bundle...
  call npm run build --workspace=client
)

echo [*] Starting full-stack servers...
echo [*] Keep this terminal window open while using the application.
echo [*] Once ready, your browser will open http://localhost:8080 automatically.
echo.

:: 5. Background watcher: opens browser automatically once port 8080 is actively listening
start "" powershell -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command "$a = 0; while ($a -lt 120) { try { $c = New-Object System.Net.Sockets.TcpClient('127.0.0.1', 8080); if ($c.Connected) { $c.Close(); Start-Process 'http://localhost:8080'; break } } catch {}; Start-Sleep -Milliseconds 500; $a++ }"

:: 6. Start the full-stack development server
call npm run dev

echo.
echo Servers stopped.
pause
