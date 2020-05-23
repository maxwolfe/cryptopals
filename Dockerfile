FROM python:3.8-slim-buster

RUN apt-get update
RUN apt-get -y install enchant
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
ENTRYPOINT [ "python" ]
CMD ["app.py"]
