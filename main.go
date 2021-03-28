package main

import (
	"flag"
	"regexp"

	"github.com/hpcloud/tail"
	log "github.com/sirupsen/logrus"
)

var (
	logdir   string
	maxretry int
	counter  int
	IPregeX  = regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
)

func init() {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	logfile := flag.String("logfile", "/var/log/messages", "logfile of mqtt service")
	max := flag.Int("maxretry", 5, "maxretry auth from one ip")
	flag.Parse()
	logdir = *logfile
	maxretry = *max
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
