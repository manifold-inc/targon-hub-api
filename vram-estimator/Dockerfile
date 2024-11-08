FROM pytorch/pytorch:latest

WORKDIR /app


# Make sure we arent missing anything
COPY requirements.txt . 
RUN pip install --no-cache-dir --upgrade -r requirements.txt
COPY ./main.py .

HEALTHCHECK --interval=1s --timeout=5s --retries=15 CMD curl --silent --fail http://localhost > /dev/null || exit 1

ENTRYPOINT ["uvicorn", "main:app", "--port", "80", "--host", "0.0.0.0"]
