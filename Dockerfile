FROM python:3-alpine

RUN apk add gcc musl-dev libffi-dev openssl-dev
WORKDIR /etc/src/app

COPY . .

RUN pip install -r requirements.txt

CMD [ "python", "client.py" ]