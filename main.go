package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/http"
	"regexp"

	"github.com/hpcloud/tail"
	log "github.com/sirupsen/logrus"
)

var (
	logdir   string
	maxretry int
	counter  int
	IPregeX  = regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
	WebHook  string
)

/*
const (
	Tables = "iptables -A INPUT -s %s -p tcp --destination-port %s -j DROP"
)
*/

func init() {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	logfile := flag.String("logfile", "/var/log/messages", "logfile of mqtt service")
	Hook := flag.String("Discord", "https://discord.com/api/webhooks/xxxxxxxxxxxxxxxxxxx/xxxxxxxxxxxxxxxxxxx", "Discord web hook URL")
	max := flag.Int("maxretry", 5, "maxretry auth from one ip")
	flag.Parse()
	logdir = *logfile
	maxretry = *max
	if *Hook != "" {
		WebHook = *Hook
	}
}

func main() {
	t, err := tail.TailFile(logdir, tail.Config{Follow: true})
	if err != nil {
		log.Panic(err)
	}
	tmpIP := make(map[string]int)
	for line := range t.Lines {
		Text := line.Text
		if match, _ := regexp.MatchString("New connection", Text); match {
			counter++
			submatchall := IPregeX.FindAllString(Text, -1)
			for _, element := range submatchall {
				if tmpIP[element] == 0 {
					tmpIP[element] = counter
				}
				for key, val := range tmpIP {
					if key == element && val != -1 {
						tmpIP[element] = counter
						if val > maxretry {
							tmpIP[element] = -1
							log.WithFields(log.Fields{
								"IP address": key,
							}).Warn("New sus ip address ඞඞඞ")
							PostCurl(key)
						}
					}
				}
			}
		}
		if match, _ := regexp.MatchString("New client connected", Text); match {
			submatchall := IPregeX.FindAllString(Text, -1)
			log.WithFields(log.Fields{
				"IP address": submatchall,
			}).Warn("New mqtt login from IP")
		}
	}
}

func PostCurl(ip string) {
	PayloadBytes, err := json.Marshal(map[string]interface{}{
		"content": nil,
		"embeds": []interface{}{
			map[string]interface{}{
				"title":       "New sus ip address ඞඞඞ",
				"description": "IP Addr\n" + ip,
				"color":       5814783,
				"author": map[string]interface{}{
					"name":     "New sus",
					"icon_url": "https://assets.stickpng.com/images/6002f9d851c2ec00048c6c78.png",
				},
			},
		},
	})
	if err != nil {
		log.Error(err)
	}
	body := bytes.NewReader(PayloadBytes)
	req, err := http.NewRequest("POST", WebHook, body)
	if err != nil {
		log.Error(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error(err)
	}
	defer resp.Body.Close()
}
