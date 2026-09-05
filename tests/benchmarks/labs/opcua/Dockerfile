FROM python:3.12-slim
RUN pip install --no-cache-dir "asyncua>=1.0,<2.0"
COPY server.py /server.py
EXPOSE 4840
CMD ["python", "/server.py"]
