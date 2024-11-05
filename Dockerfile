FROM python:3.9-slim

RUN apt-get update && apt-get install -y nodejs npm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /peercast

COPY requirements.txt /peercast/
RUN pip install -r requirements.txt

COPY package.json /peercast/
RUN npm install

COPY . /peercast/

RUN npm run build

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
