FROM python:3.11.8-bookworm

WORKDIR /app

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN apt-get update && apt-get upgrade -y
# Install bittensor
## Install dependencies
RUN apt-get install -y curl sudo nano git htop netcat-openbsd wget unzip tmux apt-utils cmake build-essential
RUN apt-get install libsoup2.4-dev javascriptcoregtk-4.0 libgtk-3-dev -y
RUN apt-get install webkit2gtk-4.0 -y
RUN pip install pywry
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python",  "-u", "cache.py"]
