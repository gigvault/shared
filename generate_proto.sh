#!/bin/bash

echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                                                                   ║"
echo "║        📝 PROTOBUF CODE GENERATION 📝                             ║"
echo "║                                                                   ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""

# Check if protoc is installed
if ! command -v protoc &> /dev/null; then
    echo "⚠️  protoc not found! Installing..."
    echo ""
    
    # For macOS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "🍎 macOS detected, installing via Homebrew..."
        brew install protobuf
    # For Linux
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "🐧 Linux detected..."
        echo "Please run: sudo apt-get install -y protobuf-compiler"
        exit 1
    fi
fi

echo "✅ protoc installed: $(protoc --version)"
echo ""

# Install Go plugins
echo "📦 Installing Go protoc plugins..."
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
echo "✅ Plugins installed"
echo ""

# Generate Go code
echo "🔨 Generating Go code from proto files..."
echo ""

cd api/proto

for proto in *.proto; do
    if [ "$proto" != "*.proto" ]; then
        echo "   📝 Generating $proto..."
        protoc --go_out=. --go_opt=paths=source_relative \
               --go-grpc_out=. --go-grpc_opt=paths=source_relative \
               "$proto"
    fi
done

cd ../..

echo ""
echo "✅ Proto generation completed!"
echo ""

# Check generated files
echo "📂 Generated files:"
ls -la api/proto/*.pb.go 2>/dev/null || echo "⚠️  .pb.go files not found"
echo ""

# Update dependencies
echo "📦 Updating dependencies..."
go get google.golang.org/grpc@latest
go get google.golang.org/protobuf@latest
go mod tidy
echo "✅ Dependencies updated"
echo ""

echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                                                                   ║"
echo "║        ✅ PROTOBUF GENERATION COMPLETED! ✅                       ║"
echo "║                                                                   ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
