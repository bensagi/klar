package main

import (
	"fmt"
	"github.com/Portshift/klar/clair"
	"github.com/Portshift/klar/docker"
	"github.com/Portshift/klar/forwarding"
	vulutils "github.com/Portshift/klar/utils/vulnerability"
	log "github.com/sirupsen/logrus"
	"os"
)

func exit(code int, conf *config, scanResults *forwarding.ImageVulnerabilities) {
	if err := forwarding.SendScanResults(conf.ResultServicePath, scanResults); err != nil {
		log.Errorf("Failed to send and scan results: %v", err)
	}
	os.Exit(code)
}

func getImageName() (string, error) {

	return os.Args[1], nil
}

func executeScan(conf *config) ([]*clair.Vulnerability, error) {
	image, err := docker.NewImage(&conf.DockerConfig)

	err = image.Pull()

	if len(image.FsLayers) == 0 {
		return nil, fmt.Errorf("failed to pull pull fsLayers")
	}

	var vulnerabilities []*clair.Vulnerability

	c := clair.NewClair(conf.ClairAddr, conf.ClairTimeout)
	vulnerabilities, err = c.Analyse(image)
	if err != nil {
		log.Errorf("Failed to analyze using API and content: %s", err)
	} else {
		
	}

	return vulnerabilities, err
}

func main() {

	result := &forwarding.ImageVulnerabilities{
		Success:  false,
		ScanUUID: os.Getenv("SCAN_UUID"),
	}

	imageName, err := getImageName()

	result.Image = imageName

	conf, err := newConfig(imageName)

	vulnerabilities, err := executeScan(conf)
	if err != nil {
		errStr := fmt.Sprintf("Failed to execute scan: %v", err)
		log.Errorf(errStr)
		result.ScanErrMsg = errStr
		exit(2, conf, result)
	}

	result.Vulnerabilities = filterVulnerabilities(conf.ClairOutput, vulnerabilities)
	result.Success = true

	vsNumber := printVulnerabilities(conf, vulnerabilities)

	if conf.Threshold != 0 && vsNumber > conf.Threshold {
		exit(1, conf, result)
	}

	if err := forwarding.SendScanResults(conf.ResultServicePath, result); err != nil {
		log.Errorf("Failed to send scan results: %v", err)
	}
}

func initLogs() {
	if os.Getenv(optionKlarTrace) == "true" {
	}
}

func filterVulnerabilities(severityThresholdStr string, vulnerabilities []*clair.Vulnerability) []*clair.Vulnerability {
	var ret []*clair.Vulnerability

	severityThreshold := vulutils.GetSeverityFromString(severityThresholdStr)
	for _, vulnerability := range vulnerabilities {
		if vulutils.GetSeverityFromString(vulnerability.Severity) < severityThreshold {
			log.Debugf("Vulnerability severity below threshold. vulnerability=%+v, threshold=%+v", vulnerability,
				severityThresholdStr)
			continue
		}
		ret = append(ret, vulnerability)
	}

	return ret
}
