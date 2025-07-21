# Install backend dependencies
Write-Host "Installing backend dependencies..."
pip install -r backend/requirements.txt

# Install frontend dependencies
Write-Host "Installing frontend dependencies..."
cd frontend
npm install
cd ..

# Start backend server in background using module mode
Write-Host "Starting backend server on http://localhost:8000 ..."
Start-Process powershell -ArgumentList 'cd backend; python -m main' -WindowStyle Hidden

# Start frontend server in background
Write-Host "Starting frontend server on http://localhost:5173 ..."
Start-Process powershell -ArgumentList 'cd frontend; npm start' -WindowStyle Hidden

Write-Host "\nBoth servers are starting. Open http://localhost:5173 in your browser to use the app." 