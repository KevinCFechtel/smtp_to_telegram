cat /lib/systemd/system/smtp_to_telegram.service 
[Unit]
Description=SMTP To Telegram

[Service]
ExecStart=/usr/local/bin/smtp_to_telegram --configFilePath /root/config.json
User=root
Group=root
UMask=007

[Install]
WantedBy=multi-user.target