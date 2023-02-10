FROM mitmproxy/mitmproxy
# RUN apt-get update && apt-get install -y build-essential python-dev
# RUN wget https://snapshots.mitmproxy.org/5.2/mitmproxy-5.2-linux.tar.gz && tar -zxvf mitmproxy-5.2-linux.tar.gz -C /bin/
COPY . /code
WORKDIR /code
RUN pip install -r requirements.txt


