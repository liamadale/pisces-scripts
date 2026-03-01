FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt -r mcp/mantis/requirements.txt
CMD ["python", "mcp/mantis/server.py"]
