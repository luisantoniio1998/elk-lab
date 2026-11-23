# ELK Security Lab

I use this lab to practise collecting and parsing Nginx logs with Filebeat and Elasticsearch. OWASP Juice Shop provides the web app, and Kibana is where I inspect the events.

## What this lab does

- Sends web traffic through Nginx
- Collects server logs with Filebeat
- Parses the logs in Elasticsearch
- Flags requests matching patterns such as SQL injection, XSS, and path traversal
- Lets you explore the events in Kibana

## What you need

- Docker
- Docker Compose
- 8GB RAM minimum
- Ports free: 5601, 8080, 9200

## Quick start

1. Clone the repo

```bash
git clone https://github.com/luisantoniio1998/elk-lab.git
cd elk-lab
```

2. Start the stack

```bash
docker-compose up -d
```

This brings up:

- Elasticsearch at http://localhost:9200
- Kibana at http://localhost:5601
- Nginx at http://localhost:8080
- OWASP Juice Shop
- Filebeat

3. Wait a bit and install the pipelines

```bash
sleep 60
./setup-pipeline.sh
```

4. Open Kibana

Go to:

- http://localhost:5601

Login:

- Username: elastic
- Password: changeme

5. Create an index pattern

In Kibana:

- Stack Management -> Index Patterns
- Create index pattern
- Use: filebeat-*
- Select time field: @timestamp

6. Search for detected attacks

In Discover, run:

```kql
security.threat_detected: true
```

## What is inside

```text
elk-lab/
├── docker-compose.yml
├── README.md
├── START-HERE.md
├── SECURITY-TESTING-GUIDE.md
├── nginx/
│   ├── nginx.conf
│   └── entrypoint.sh
├── filebeat/
│   └── filebeat.yml
├── nginx-pipeline.json
├── nginx-error-pipeline.json
├── setup-pipeline.sh
└── .env
```

## Patterns in the pipelines

The pipeline rules cover these patterns in the logs:

- SQL injection
- XSS
- Path traversal
- Command injection
- Failed logins
- Scanner traffic
- Suspicious HTTP methods
- Upstream errors

## How it works

Traffic goes through Nginx, then Filebeat reads the logs and sends them to Elasticsearch. Elasticsearch uses ingest pipelines to parse the requests and add security fields. Then you can look at the data in Kibana and build dashboards.

## Quick attack checks

Once the lab is running, you can test a few requests:

```bash
curl "http://localhost:8080/api/Products?id=1%27%20OR%20%271%27=%271"
curl "http://localhost:8080/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
curl "http://localhost:8080/ftp/../../etc/passwd"
```

Then check for hits in Kibana:

```kql
security.threat_detected: true
```

## Troubleshooting

### Elasticsearch won't start

Check logs:

```bash
docker logs elasticsearch
```

If memory is low, increase Docker memory to at least 8GB.

### No logs in Kibana

```bash
docker logs filebeat
```

Also check that the pipelines were installed:

```bash
curl -u elastic:changeme http://localhost:9200/_ingest/pipeline | jq 'keys'
```

### Nginx logs not showing up

```bash
docker exec nginx_proxy ls -lh /var/log/nginx/
```

If needed, restart the Nginx container.

## Useful docs

- START-HERE.md — setup details
- SECURITY-TESTING-GUIDE.md — attack examples

## Contributing

Open an issue or submit a PR if you want to add detections, improve docs, or fix something.

## License

MIT

## Lab scope

This is a local learning setup. The pattern matches are examples to inspect and refine, rather than proof that an attack succeeded.
