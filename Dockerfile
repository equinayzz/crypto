# Gunakan base image Python
FROM python:3.9-slim

# Set working directory di dalam container
WORKDIR /app

# Salin semua file aplikasi ke dalam container
COPY . /app/

# Install dependencies Flask, pymongo, pycryptodome, dan Flask-HTTPAuth
RUN pip install -r requirements.txt

# Expose port 5000 untuk Flask
EXPOSE 5000

# Menyalin file HTML ke dalam direktori templates di dalam container
COPY templates /app/templates

# Menjalankan aplikasi Flask saat container dimulai
CMD ["python", "./crypto_api.py"]
