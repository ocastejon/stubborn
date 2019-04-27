#!/bin/bash

# start cron
/etc/init.d/cron start

chown -R stubborn:stubborn /stubborn/tmp

# start stubborn
su stubborn -c "python /stubborn/app.py"