FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt -r mcp/kibana/requirements.txt
CMD ["python", "mcp/kibana/server.py"]
