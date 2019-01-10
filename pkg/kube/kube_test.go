package kube

import (
	"testing"

	"k8s.io/api/core/v1"
)

func TestTerminatedReason(t *testing.T) {
	pod := v1.Pod{Status: v1.PodStatus{
		ContainerStatuses: []v1.ContainerStatus{
			v1.ContainerStatus{
				State: v1.ContainerState{Terminated: &v1.ContainerStateTerminated{
					Reason: "Completed"}},
			},
			v1.ContainerStatus{
				State: v1.ContainerState{Running: &v1.ContainerStateRunning{}},
			},
		}}}

	result := getTerminationReason(&pod)
	if result != "Completed" {
		t.Errorf("terminated reason should be Completed got: %v", result)
	}

	pod = v1.Pod{Status: v1.PodStatus{
		ContainerStatuses: []v1.ContainerStatus{
			v1.ContainerStatus{
				State: v1.ContainerState{Terminated: &v1.ContainerStateTerminated{
					Reason: "Error"}},
			},
			v1.ContainerStatus{
				State: v1.ContainerState{Running: &v1.ContainerStateRunning{}},
			},
		}}}

	result = getTerminationReason(&pod)
	if result != "Error" {
		t.Errorf("terminated reason should be Error got: %v", result)
	}

	pod = v1.Pod{Status: v1.PodStatus{
		ContainerStatuses: []v1.ContainerStatus{
			v1.ContainerStatus{
				State: v1.ContainerState{Running: &v1.ContainerStateRunning{}},
			},
			v1.ContainerStatus{
				State: v1.ContainerState{Running: &v1.ContainerStateRunning{}},
			},
		}}}

	result = getTerminationReason(&pod)
	if result != "" {
		t.Errorf("terminated reason should be nil got: %v", result)
	}
}
