package metrics

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	kapierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	"github.com/prometheus/common/model"
)

const (
	serviceCAinjectionDataKey             = "service-ca.crt"
	serviceCAinjectCABundleAnnotationName = "service.beta.openshift.io/inject-cabundle"
	metricsBaseURL                        = "https://prometheus-k8s.openshift-monitoring.svc:9091"
)

type PrometheusClient struct {
	Client      *http.Client
	URL         string
	BearerToken string
}

func NewPrometheusClient(caBundle []byte, query, bearerToken string) (*PrometheusClient, error) {
	url := fmt.Sprintf("%s/api/v1/query?%s", metricsBaseURL, (url.Values{"query": []string{query}}).Encode())
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caBundle)
	tlsConfig := &tls.Config{
		RootCAs: certPool,
	}

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	tlsClient := &http.Client{Transport: tr}
	return &PrometheusClient{
		Client:      tlsClient,
		URL:         url,
		BearerToken: bearerToken,
	}, nil
}

func LocatePrometheus(client *kubernetes.Clientset) (string, bool) {
	_, err := client.CoreV1().Services("openshift-monitoring").Get("prometheus-k8s", metav1.GetOptions{})
	if kapierrs.IsNotFound(err) {
		return "", false
	}

	var bearerToken string
	err = wait.Poll(time.Second*1, time.Second*30, func() (bool, error) {
		secrets, err := client.CoreV1().Secrets("openshift-monitoring").List(metav1.ListOptions{})
		if err != nil {
			return false, fmt.Errorf("could not list secrets in openshift-monitoring namespace")
		}
		for _, secret := range secrets.Items {
			if secret.Type != corev1.SecretTypeServiceAccountToken {
				continue
			}
			if !strings.HasPrefix(secret.Name, "prometheus-") {
				continue
			}
			bearerToken = string(secret.Data[corev1.ServiceAccountTokenKey])
			break
		}
		if len(bearerToken) == 0 {
			return false, fmt.Errorf("waiting for premetheus bearer token")
		} else {
			return true, nil
		}
	})
	if err != nil {
		return "", false
	}
	return bearerToken, true
}

const waitForPrometheusStartSeconds = 240

type prometheusResponse struct {
	Status string                 `json:"status"`
	Data   prometheusResponseData `json:"data"`
}

type prometheusResponseData struct {
	ResultType string       `json:"resultType"`
	Result     model.Vector `json:"result"`
}

func (pq *PrometheusClient) getQueryResponse() ([]byte, error) {
	//cmd := fmt.Sprintf("curl -s -k -H 'Authorization: Bearer %s' %q", bearer, url)
	req, err := http.NewRequest("GET", pq.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", pq.BearerToken)

	resp, err := pq.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("curl command failed: %v\n%v", err, resp)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	return body, nil
}

// RunPrometheusQuery() checks that query returns non-empty result, errors if query returns empty, and returns metrics
// example: query := `ALERTS{alertstate="pending",alertname="PodDisruptionBudgetAtLimit",severity="warning"} == 1`
func (pq *PrometheusClient) RunPrometheusQuery() (model.Vector, error) {
	// expect all correct metrics within a reasonable time period
        var metrics model.Vector
	err := wait.Poll(time.Second*1, time.Second*waitForPrometheusStartSeconds, func() (bool, error) {
		//TODO when the http/query apis discussed at https://github.com/prometheus/client_golang#client-for-the-prometheus-http-api
		// and introduced at https://github.com/prometheus/client_golang/blob/master/api/prometheus/v1/api.go are vendored into
		// openshift/origin, look to replace this homegrown http request / query param with that API
		contents, err := pq.getQueryResponse()
		if err != nil {
			return false, fmt.Errorf("waiting for query results from %s", pq.URL)
		}
		result := prometheusResponse{}
		json.Unmarshal(contents, &result)
		metrics = result.Data.Result

		if len(metrics) == 0 {
			return false, fmt.Errorf("prometheus query url: %s has reported incorrect results: %v", pq.URL, metrics)
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return metrics, nil
}

func RetrieveServiceCABundle(client *kubernetes.Clientset, configMapName, nsName string) ([]byte, error) {
	// Prompt the injection of the ca bundle into a configmap
	err := createAnnotatedCABundleInjectionConfigMap(client, configMapName, nsName)
	if err != nil {
		return nil, fmt.Errorf("error creating annotated configmap: %v", err)
	}

	// Retrieve the ca bundle
	expectedDataSize := 1
	var ca []byte
	err = wait.Poll(time.Second*1, time.Second*30, func() (bool, error) {
		configMap, err := client.CoreV1().ConfigMaps(nsName).Get(configMapName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if len(configMap.Data) != expectedDataSize {
			return false, fmt.Errorf("expected data size %d, got %d", expectedDataSize, len(configMap.Data))
		}
		_, ok := configMap.Data[serviceCAinjectionDataKey]
		if !ok {
			return false, fmt.Errorf("key %q is missing", serviceCAinjectionDataKey)
		}
		ca = []byte(configMap.Data[serviceCAinjectionDataKey])
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return ca, nil
}

func createAnnotatedCABundleInjectionConfigMap(client *kubernetes.Clientset, configMapName, nsName string) error {
	_, err := client.CoreV1().ConfigMaps(nsName).Create(&corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: configMapName,
			Annotations: map[string]string{
				serviceCAinjectCABundleAnnotationName: "true",
			},
		},
	})
	return err
}
