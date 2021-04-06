#### mqtt-bruteforce

simple ids to detect auth from internet to mqtt like mosquitto  

##### How to use

```
go mod download
go build -o kano_def
./kano_def -logfile {path to mosquitto logfile} -maxretry 3
or use discord webhook to send notif
./kano_def -logfile {path to mosquitto logfile} -maxretry 3 -Discord https://discord.com/api/webhooks/xxxxxxxxxxxxxxxxxxx/xxxxxxxxxxxxxxxxxxx
```

##### Example
<p align="center">
  <img src="https://raw.githubusercontent.com/JustHumanz/simpe-mqtt-ids/master/img.png" alt="Setup"/>
</p>  
