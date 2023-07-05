package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"C"

	"github.com/fluent/fluent-bit-go/output"

	rhttp "github.com/hashicorp/go-retryablehttp"
)

import (
	"io/ioutil"
	"sync"
	"unsafe"
)

var (
	plugins  sync.Map
	rhc      *rhttp.Client
	hc_setup sync.Mutex
)

func init() {
	plugins = sync.Map{}
}

type Config struct {
	URL string
	Key string
}

func getURLWithPath(schema, host, port, path string) string {
	u := &url.URL{
		Scheme: schema,
		Host:   net.JoinHostPort(host, port),
		Path:   path,
	}
	return u.String()
}

func getURL(schema, host, port, path, topic string) string {
	u := &url.URL{
		Scheme: schema,
		Host:   net.JoinHostPort(host, port),
		Path:   path + "/topics/" + topic,
	}
	return u.String()
}

func toMapStringInterface(inputRecord map[interface{}]interface{}) map[string]interface{} {
	return parseValue(inputRecord).(map[string]interface{})
}

func parseValue(value interface{}) interface{} {
	switch value := value.(type) {
	case []byte:
		return string(value)
	case map[interface{}]interface{}:
		remapped := make(map[string]interface{})
		for k, v := range value {
			remapped[k.(string)] = parseValue(v)
		}
		return remapped
	case []interface{}:
		remapped := make([]interface{}, len(value))
		for i, v := range value {
			remapped[i] = parseValue(v)
		}
		return remapped
	default:
		return value
	}
}

func toKafkaRestFormat(data []map[string]interface{}) *bytes.Buffer {
	values := make([]string, len(data))
	for i, u := range data {
		encoded, err := json.Marshal(u)
		if err != nil {
			log.Printf("[deepfence] error marshal doc %s\ndoc:%s", err, u)
			continue
		}
		values[i] = "{\"value\":" + string(encoded) + "}"
	}
	result := strings.Join(values, ",")
	return bytes.NewBuffer([]byte("{\"records\":[" + result + "]}"))
}

//export FLBPluginInit
func FLBPluginInit(ctopic, chost, cport, cpath, cschema, ckey, ccertPath, ccertKey *C.char) int {
	topic := C.GoString(ctopic)
	host := C.GoString(chost)
	port := C.GoString(cport)
	path := C.GoString(cpath)
	schema := C.GoString(cschema)
	certPath := C.GoString(ccertPath)
	certKey := C.GoString(ccertKey)
	key := C.GoString(ckey)

	log.Printf("id=%s schema=%s host=%s port=%s path=%s",
		topic, schema, host, port, path)

	// setup http client
	hc_setup.Lock()
	defer hc_setup.Unlock()
	if rhc == nil {
		rhc = rhttp.NewClient()
		tlsConfig := &tls.Config{RootCAs: x509.NewCertPool(), InsecureSkipVerify: true}
		rhc.HTTPClient.Timeout = 10 * time.Second
		rhc.RetryMax = 3
		rhc.RetryWaitMin = 1 * time.Second
		rhc.RetryWaitMax = 10 * time.Second
		rhc.CheckRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) {
			if err != nil || resp == nil {
				return false, err
			}
			if resp.StatusCode == http.StatusServiceUnavailable {
				return false, err
			}
			return rhttp.DefaultRetryPolicy(ctx, resp, err)
		}
		rhc.Logger = log.New(os.Stderr, "", log.LstdFlags|log.Lshortfile)
		if schema == "https" {
			if len(certPath) > 0 && len(certKey) > 0 {
				cer, err := tls.LoadX509KeyPair(certPath, certKey)
				if err != nil {
					log.Printf("%s error loading certs %s", topic, err)
					return output.FLB_ERROR
				}
				tlsConfig.Certificates = []tls.Certificate{cer}
			}
			tr := &http.Transport{
				TLSClientConfig:   tlsConfig,
				DisableKeepAlives: false,
			}
			rhc.HTTPClient = &http.Client{Transport: tr}
		}
	}

	pushed, _ := plugins.LoadOrStore(topic, Config{
		URL: getURL(schema, host, port, path, topic),
		Key: key,
	})

	log.Printf("api token set %t for id %s, for url %s", key != "", topic, pushed.(Config).URL)

	return output.FLB_OK
}

//export FLBPluginFlushCtx
func FLBPluginFlushCtx(cid *C.char, data unsafe.Pointer, length C.int) int {
	id := C.GoString(cid)
	e, ok := plugins.Load(id)
	if !ok {
		log.Printf("push to unknown id topic %s", id)
		return output.FLB_ERROR
	}
	idCfg := e.(Config)
	// fluentbit decoder
	dec := output.NewDecoder(data, int(length))

	records := make([]map[string]interface{}, 0)

	for {
		ret, _, record := output.GetRecord(dec)
		if ret != 0 {
			break
		}
		records = append(records, toMapStringInterface(record))
	}

	req, err := rhttp.NewRequest(http.MethodPost, idCfg.URL, toKafkaRestFormat(records))
	if err != nil {
		log.Printf("[deepfence] error creating request %s", err)
		return output.FLB_ERROR
	}
	if idCfg.Key != "" {
		req.Header.Add("deepfence-key", idCfg.Key)
	}
	req.Header.Add("Content-Type", "application/vnd.kafka.json.v2+json")

	resp, err := rhc.Do(req)
	if err != nil {
		if os.IsTimeout(err) {
			// timeout error
			log.Printf("[deepfence] retry request timeout error: %s", err)
			return output.FLB_RETRY
		}
		log.Printf("[deepfence] error making request %s", err)
		return output.FLB_ERROR
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable ||
		resp.StatusCode == http.StatusGatewayTimeout || resp.StatusCode == http.StatusTooManyRequests {
		log.Printf("[deepfence] retry response code %s", resp.Status)
		return output.FLB_RETRY
	} else if resp.StatusCode != http.StatusOK {
		log.Printf("[deepfence] error response code %s", resp.Status)
		return output.FLB_ERROR
	}

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[deepfence] error reading response %s", err)
		return output.FLB_ERROR
	}

	return output.FLB_OK
}

func main() {}
