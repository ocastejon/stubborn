FROM python:3

RUN apt-get update && apt-get install -y cmake cron mingw-w64

RUN groupadd -r stubborn && useradd -m -g stubborn stubborn
COPY --chown=stubborn:stubborn config/stubborn-crontab /var/spool/cron/crontabs/stubborn
RUN chmod 0600 /var/spool/cron/crontabs/stubborn

COPY config/start.sh /root/start.sh

WORKDIR /stubborn
COPY app/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
ENV FLASK_ENV development

#COPY . .

ENTRYPOINT [ "bash", "/root/start.sh" ]
