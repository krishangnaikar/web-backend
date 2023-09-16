FROM python:3.10.5-slim-buster

RUN apt-get -y update && apt-get -y upgrade

RUN apt-get -y install vim

WORKDIR /app

COPY . .

COPY requirements.txt /app/requirements.txt

RUN pip install -r requirements.txt

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "80"]
