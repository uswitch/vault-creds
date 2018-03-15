package kube

import (
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

//CheckStatus checks the staus of the other containers
func CheckStatus(clientSet *kubernetes.Clientset, namespace, podName string) (string, error) {

	pod, err := clientSet.CoreV1().Pods(namespace).Get(podName, v1.GetOptions{})
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
