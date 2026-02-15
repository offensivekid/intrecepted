#!/bin/bash

echo "🔥 Starting OFFENSIVE FORUM..."
echo ""

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
    echo ""
fi

echo "🚀 Starting server on http://localhost:8080"
echo "Press Ctrl+C to stop"
echo ""

npm start
