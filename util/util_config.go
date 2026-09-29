//
// Copyright IBM Corp. 2025 - 2026
// SPDX-License-Identifier: Apache-2.0
//

package util

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

type SinglePod struct {
	Apiversion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Status struct {
		Phase string `json:"phase"`
	} `json:"status"`
}

type PodList struct {
	Items []struct {
		Metadata struct {
			Name        string            `json:"name"`
			Namespace   string            `json:"namespace"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Status struct {
			Phase string `json:"phase"`
		} `json:"status"`
	} `json:"items"`
}

func CheckCCOPEnabled(nameSpace string, podName string, kbsAuthKey string) error {
	args := []string{"get", "pod", "-o", "json", podName}

	if nameSpace != "" {
		args = append(args, "-n")
		args = append(args, nameSpace)

	}

	cmd := exec.Command("kubectl", args...) // #nosec G204 -- fixed binary name; args are pod/namespace from CLI flags
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to kubectl get pod %s: %v", podName, err)
	}

	var pod SinglePod
	if err := json.Unmarshal(output, &pod); err != nil {
		return fmt.Errorf("failed to parse pod's JSON: %v", err)
	}

	if pod.Status.Phase != "Running" {
		return fmt.Errorf("pod is not running: %v", err)
	}

	annotations := pod.Metadata.Annotations
	if annotations == nil {
		return fmt.Errorf("pod has no annotations: %v", err)
	}

	data, ok := annotations["io.katacontainers.config.hypervisor.cc_init_data"]
	if !ok || data == "" {
		return fmt.Errorf("pod has no cc_init_data: %v", err)
	}

	decoded, err := decodeAndDecompress(data)
	if err != nil {
		return fmt.Errorf("error decoding cc_init_data: %v", err)
	}

	// fmt.Println(string(decoded))
	initData, err := parseInitDataToml(decoded)
	if err != nil {
		return fmt.Errorf("pod %s: failed to parse TOML: %w", podName, err)
	}

	ccopToml, ok := initData.Data["ccop.toml"]
	if !ok {
		return fmt.Errorf("pod's initdata has no ccop.toml defined")
	}

	_, err = ccopTomlHasAuthCert(ccopToml)
	if err != nil {
		return fmt.Errorf("pod %s: error: failed to parse data.ccop.toml: %w", podName, err)
	}

	if kbsAuthKey != "" {
		cdhToml, ok := initData.Data["cdh.toml"]
		if !ok {
			return fmt.Errorf("\tcdh.toml: not found")
		}

		_, kbsUrl, err := cdhTomlKbsUrl(cdhToml)
		if err != nil {
			return fmt.Errorf("\tcdh.toml.url: not found %v", err)
		}

		err = retrieve_agent_cert(nameSpace, podName, kbsUrl, kbsAuthKey)
		if err != nil {
			return fmt.Errorf("\terror: retrieving agent cert %v", err)
		}

		err = retrieve_random_bytes(nameSpace, podName, kbsUrl, kbsAuthKey)
		if err != nil {
			return fmt.Errorf("\terror: retrieving random bytes %v", err)
		}
	}

	return nil
}

func ListWorkload() error {
	// process all running pods!
	cmd := exec.Command("kubectl", "get", "pods", "-A", "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		log.Fatal("failed to run kubectl:", err)
	}

	var podList PodList
	if err := json.Unmarshal(output, &podList); err != nil {
		log.Fatal("failed to parse JSON:", err)
	}

	for _, pod := range podList.Items {
		// Only running pods
		if pod.Status.Phase != "Running" {
			continue
		}

		annotations := pod.Metadata.Annotations
		if annotations == nil {
			continue
		}

		podName := pod.Metadata.Name
		if podName == "" {
			continue
		}

		podNamespace := pod.Metadata.Namespace
		if podName == "" {
			continue
		}

		data, ok := annotations["io.katacontainers.config.hypervisor.cc_init_data"]
		if !ok || data == "" {
			fmt.Printf("\n=== Pod: %s/%s ===\n", podNamespace, podName)
			continue
		}

		fmt.Printf("\n=== Pod: %s/%s ===\n", podNamespace, podName)
		decoded, err := decodeAndDecompress(data)
		if err != nil {
			fmt.Printf("Error decoding: %v\n", err)
			continue
		}

		// fmt.Println(string(decoded))
		initData, err := parseInitDataToml(decoded)
		if err != nil {
			msg := fmt.Sprintf("pod %s: failed to parse TOML: %v\n", podName, err)
			fmt.Println(msg)
			continue
		}

		if strings.TrimSpace(initData.Algorithm) == "" {
			fmt.Printf("pod %s: algorithm field missing\n", podName)
			continue
		}
		//fmt.Printf("pod %s: algorithm=%s\n", pod.Metadata.Name, initData.Algorithm)
		fmt.Printf("\talgorithm: %s\n", initData.Algorithm)

		// compute hash of decoded initdata using algorithm
		digest, err := computeDigest(initData.Algorithm, string(decoded))
		if err != nil {
			fmt.Printf("error: failed to compute digest: %v\n", err)
			continue
		}
		fmt.Printf("\tdigest: %s\n", digest)

		//cdhToml, ok := initData.Data["cdh.toml"]

		ccopToml, ok := initData.Data["ccop.toml"]
		if !ok {
			fmt.Printf("\tinitdata ccop.toml: not found\n")
			continue
		}
		fmt.Printf("\tccop.toml: defined\n")

		hasAuthCert, err := ccopTomlHasAuthCert(ccopToml)
		if err != nil {
			//fmt.Printf("error: failed to parse data.ccop.toml: %v\n", podName, err)
			fmt.Printf("\tfailed to parse data.ccop.toml: %v\n", err)
			continue
		}

		if !hasAuthCert {
			fmt.Printf("\tdata.ccop.toml auth_cert not set\n")
			continue
		}
		fmt.Printf("\tccop.toml.auth_cert: set\n")

		cdhToml, ok := initData.Data["cdh.toml"]
		if !ok {
			fmt.Printf("\tcdh.toml: not found\n")
			continue
		}

		//fmt.Printf("\tinitdata cdh.toml: defined %s\n", cdhToml)
		fmt.Printf("\tcdh.toml: defined \n")

		kbsName, kbsUrl, err := cdhTomlKbsUrl(cdhToml)
		if err != nil {
			fmt.Printf("\tcdh.toml.url: not found %v\n", err)
			continue
		}
		fmt.Printf("\tcdh.toml.kbs: %s\n", kbsName)
		fmt.Printf("\tcdh.toml.url: %s\n", kbsUrl)

	}

	return nil
}

func decodeAndDecompress(input string) ([]byte, error) {
	// decode obase64
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	// decompress
	reader, err := gzip.NewReader(bytes.NewReader(decoded))
	if err != nil {
		return nil, fmt.Errorf("gzip reader failed: %w", err)
	}
	defer reader.Close()

	result, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}

	return result, nil
}

func computeDigest(algorithm string, data string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "sha256":
		sum := sha256.Sum256([]byte(data))
		return base64.StdEncoding.EncodeToString(sum[:]), nil
	case "sha384":
		sum := sha512.Sum384([]byte(data))
		return base64.StdEncoding.EncodeToString(sum[:]), nil
	case "sha512":
		sum := sha512.Sum512([]byte(data))
		return base64.StdEncoding.EncodeToString(sum[:]), nil
	default:
		return "", fmt.Errorf("unsupported algorithm %q", algorithm)
	}
}

type initDataToml struct {
	Algorithm string            `toml:"algorithm"`
	Data      map[string]string `toml:"data"`
}

func parseInitDataToml(data []byte) (*initDataToml, error) {
	var parsed initDataToml
	if _, err := toml.Decode(string(data), &parsed); err != nil {
		return nil, err
	}

	return &parsed, nil
}

func ccopTomlHasAuthCert(data string) (bool, error) {
	var parsed struct {
		AuthCert string `toml:"auth_cert"`
	}

	if _, err := toml.Decode(data, &parsed); err != nil {
		return false, err
	}

	return strings.TrimSpace(parsed.AuthCert) != "", nil
}

/*
"cdh.toml" = ”'
[kbc]
name = "cc_kbc"
url = "http://1.2.3.4:8080"
”'
*/
type cdhToml struct {
	KBC struct {
		Name string `toml:"name"`
		URL  string `toml:"url"`
	} `toml:"kbc"`
}

func cdhTomlKbsUrl(data string) (string, string, error) {
	var parsed cdhToml

	if _, err := toml.Decode(data, &parsed); err != nil {
		return "", "", err
	}

	return strings.TrimSpace(parsed.KBC.Name), strings.TrimSpace(parsed.KBC.URL), nil
}

func retrieve_agent_cert(ns string, podName string, kbsUrl string, authKeyFile string) error {

	// Save to ~/.ccop/cache/<ns>_<pod>/receiver.crt
	if podName == "" {
		return fmt.Errorf("pod name must be specified (for cache path)")
	}

	// Fixed query string: secret_name=ccop_p256 secret_type=p256
	query := fmt.Sprintf("name=%s&ns=%s&secret_name=ccop_p256&secret_type=p256", podName, ns)

	// Read the admin private key
	authKeyPEM, err := os.ReadFile(authKeyFile) // #nosec G304 -- path supplied by trusted caller
	if err != nil {
		return fmt.Errorf("failed to read auth key file")
	}

	// Fetch from KBS
	secret, err := FetchClientCreds(kbsUrl, string(authKeyPEM), query)
	if err != nil {
		return fmt.Errorf("failed to fetch client credentials")
	}

	if secret.MaterialType != "P256" {
		return fmt.Errorf("expected P256 material, got %q; ", secret.MaterialType)
	}

	certPEM := secret.CertPEM
	if len(certPEM) == 0 {
		return fmt.Errorf("server returned a P256 secret with empty cert_pem")
	}

	certPath, err := SaveCertToCache(ns, podName, certPEM)
	if err != nil {
		return fmt.Errorf("failed to save certificate to cache: %w", err)
	}

	fmt.Printf("Certificate saved to %s\n", certPath)
	return nil
}

func retrieve_random_bytes(ns string, podName string, kbsUrl string, authKeyFile string) error {

	if podName == "" {
		return fmt.Errorf("pod name must be specified (for cache path)")
	}

	// Fixed query string: secret_name=ccop_random secret_type=random
	query := fmt.Sprintf("name=%s&ns=%s&secret_name=ccop_random&secret_type=random", podName, ns)

	// Read the admin private key
	authKeyPEM, err := os.ReadFile(authKeyFile) // #nosec G304 -- path supplied by trusted caller
	if err != nil {
		return fmt.Errorf("failed to read auth key file: %w", err)
	}

	// Fetch from KBS
	secret, err := FetchClientCreds(kbsUrl, string(authKeyPEM), query)
	if err != nil {
		return fmt.Errorf("failed to fetch random bytes: %w", err)
	}

	if secret.MaterialType != "Random" {
		return fmt.Errorf("expected Random material, got %q", secret.MaterialType)
	}

	if len(secret.Bytes) == 0 {
		return fmt.Errorf("server returned a Random secret with empty bytes")
	}

	filePath, err := SaveBytesToCache(ns, podName, "ccop_random.bin", secret.Bytes)
	if err != nil {
		return fmt.Errorf("failed to save random bytes to cache: %w", err)
	}

	fmt.Printf("Random bytes saved to %s\n", filePath)
	return nil
}

// PruneCache removes cache subdirectories for pods that are no longer running.
// Cache directories follow the naming convention <namespace>_<podname>.
func PruneCache() error {
	cachePath, err := getCachePath()
	if err != nil {
		return fmt.Errorf("failed to read cache directory: %w", err)
	}

	entries, err := os.ReadDir(cachePath)
	if err != nil {
		return fmt.Errorf("failed to read cache directory: %w", err)
	}

	pruned := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		// Expect exactly one underscore separating namespace and pod name.
		idx := strings.Index(name, "_")
		if idx < 0 {
			fmt.Printf("skipping unexpected cache entry: %s\n", name)
			continue
		}
		ns := name[:idx]
		podName := name[idx+1:]
		if ns == "" || podName == "" {
			fmt.Printf("skipping malformed cache entry: %s\n", name)
			continue
		}

		running, err := isPodRunning(ns, podName)

		// Prune case: a non-zero exit with stderr containing "not found", the pod no longer exists
		if err != nil && !isNotFound(err) {
			fmt.Printf("warning: could not check pod %s/%s: %v — skipping\n", ns, podName, err)
			continue
		}

		if !running {
			dirPath := filepath.Join(cachePath, name)
			if err := os.RemoveAll(dirPath); err != nil {
				fmt.Printf("error: failed to remove %s: %v\n", dirPath, err)
				continue
			}
			fmt.Printf("pruned: %s_%s (%s)\n", ns, podName, dirPath)
			pruned++
		}
	}

	if pruned == 0 {
		fmt.Println("no stale cache entries found")
	} else {
		fmt.Printf("pruned %d stale cache entr%s\n", pruned, map[bool]string{true: "y", false: "ies"}[pruned == 1])
	}

	return nil
}

func getCachePath() (string, error) {

	cfgDir, err := GetCfgDir()
	if err != nil {
		return "", err
	}

	cachePath := filepath.Join(*cfgDir, "cache")
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		return "", fmt.Errorf("cache directory does not exist: %s", cachePath)
	}

	return cachePath, nil
}

// isNotFound returns true when kubectl exited non-zero due to a "not found" response.
// A non-zero exit with stderr containing "not found" means the pod no longer exists;
// any other error (auth failure, unreachable cluster, etc.) should not be silently pruned.
func isNotFound(err error) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	return strings.Contains(strings.ToLower(string(exitErr.Stderr)), "not found")
}

// isPodRunning returns true if the named pod exists and is in the Running phase.
// It returns (false, *exec.ExitError) when kubectl exits non-zero (e.g. pod not found).
func isPodRunning(ns string, podName string) (bool, error) {
	args := []string{"get", "pod", podName, "-n", ns, "-o", "jsonpath={.status.phase}"}
	out, err := exec.Command("kubectl", args...).Output() // #nosec G204 -- fixed binary name
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(out)) == "Running", nil
}
