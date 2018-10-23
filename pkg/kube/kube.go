package kube

import (
	"context"
	"fmt"
	"time"

	log "github.com/Sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type KubeChecker struct {
	client    *kubernetes.Clientset
	namespace string
	podName   string
}

func createClientSet(config *rest.Config) (*kubernetes.Clientset, error) {
	c, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func NewKubeChecker(pod, namespace string) (*KubeChecker, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("error creating kube client config: %s", err)
	}

	clientSet, err := createClientSet(config)
	if err != nil {
		return nil, fmt.Errorf("error creating kube client: %s", err)
	}
	return &KubeChecker{client: clientSet, podName: pod, namespace: namespace}, nil
}

//CheckStatus checks the staus of the other containers
func (k *KubeChecker) checkStatus() (string, error) {

	pod, err := k.client.CoreV1().Pods(k.namespace).Get(k.podName, v1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("error getting pod: %s", err)
	}

	for _, containers := range pod.Status.ContainerStatuses {
		if containers.State.Terminated != nil {
			return containers.State.Terminated.Reason, nil
		}
	}

	return "", nil
}

func (k *KubeChecker) Run(ctx context.Context, errChan chan int) {
	go func() {

		ticker := time.Tick(5 * time.Second)

		for {
			select {
			case <-ctx.Done():
				log.Infof("stopping checker")
				return
			case <-ticker:
				status, err := k.checkStatus()
				if err != nil {
					log.Errorf("error getting pod status: %s", err)
				}
				if status == "Error" {
					log.Error("primary container has errored")
					errChan <- 2
					return
				}
				if status == "Completed" {
					log.Infof("received completion signal")
					errChan <- 0
					return
				}
			}
		}
	}()
}
