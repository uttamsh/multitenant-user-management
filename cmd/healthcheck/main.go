// healthcheck probes readiness without needing a shell or curl in the image.
package main

import (
	"net/http"
	"os"
	"time"
)

func main() {
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://127.0.0.1:8080/ready")
	if err != nil {
		os.Exit(1)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		os.Exit(1)
	}
}
