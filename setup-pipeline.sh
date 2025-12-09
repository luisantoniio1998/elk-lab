#!/bin/bash

echo "🚀 Setting up Nginx Pipelines..."

# Wait for Elasticsearch
echo "⏳ Waiting for Elasticsearch..."
until curl -s -u elastic:${ELASTIC_PASSWORD:-changeme} http://localhost:${ES_PORT:-9200}/_cluster/health | grep -q "yellow\|green"; do
    sleep 5
    echo "   Still waiting..."
done

echo "✅ Elasticsearch is ready!"
echo ""

# Create access log pipeline
echo "📝 Creating nginx-access-parser pipeline..."
curl -X PUT "http://localhost:${ES_PORT:-9200}/_ingest/pipeline/nginx-access-parser" \
  -u elastic:${ELASTIC_PASSWORD:-changeme} \
  -H 'Content-Type: application/json' \
  -d @nginx-pipeline.json

echo ""

# Create error log pipeline
echo "📝 Creating nginx-error-parser pipeline..."
curl -X PUT "http://localhost:${ES_PORT:-9200}/_ingest/pipeline/nginx-error-parser" \
  -u elastic:${ELASTIC_PASSWORD:-changeme} \
  -H 'Content-Type: application/json' \
  -d @nginx-error-pipeline.json

echo ""
echo "✅ Both pipelines created successfully!"
echo ""
echo "🔍 Verifying pipelines..."
curl -s -u elastic:${ELASTIC_PASSWORD:-changeme} "http://localhost:${ES_PORT:-9200}/_ingest/pipeline" | grep -o '"nginx-[^"]*"' | sort

echo ""
echo "✨ Setup complete! You can now view logs in Kibana at http://localhost:5601"
