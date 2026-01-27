# 1. 使用轻量级 Python 镜像
FROM python:3.12-slim

# 2. 安装系统依赖 (Tshark)
# 注意：在 Docker 里安装 tshark 需要设置非交互模式
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y tshark && \
    rm -rf /var/lib/apt/lists/*

# 3. 设置工作目录
WORKDIR /app

# 4. 复制依赖文件并安装
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. 复制后端代码
COPY . .

# 6. 暴露 FastAPI 端口
EXPOSE 8000

# 7. 启动命令
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]