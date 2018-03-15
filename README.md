# Vault Creds

Program (and Docker container) to be run as a sidecar to your application- requesting dynamic database credentials that will be leased while the application is active.

It implements authentication according to [Vault's Kubernetes Authentication flow](https://kubernetes.io/docs/admin/authentication/).

## Usage

This project is to be deployed in a Pod alongside the main application. When `vault-creds` starts it will request credentials at the path specified and continually renew their lease.

For example:

```
$ ./bin/vaultcreds \
  --ca-cert=~/.vaultca \
  --token-file=/var/run/secrets/kubernetes.io/serviceaccount/token \
  --login-path=kubernetes/cluster/login \
  --auth-role=service_account_role \
  --template=sample.database.yml \
  --secret-path=database/creds/database_role
INFO[0000] authenticated                                 policies="[default service_account_role]"
production:
  adapter: postgresql
  database: my_database
  host: mydbhost
  username: v-kubernet-app-3q9s0x28tv6xzt2yx87x-1516141848
  password: XXXXXXXXXXXXXX
INFO[0000] renewing 1h0m0s lease every 1m0s
```

The template is applied to the latest credentials and written to `--out` (normally this would be a shared mount for the other containers read).

## Job Mode

Kubernetes doesn't handle sidecars in cronjobs/jobs very well as it has no understanding of the difference between the primary container and the sidecar, this means that if your primary process errors/completes the job will continue to run as the vault-creds sidecar will still be running.

To get around this you can run the sidecar with `--job` flag which will cause the vault-creds sidecar to watch the status of the other containers in the pod. If they error the vault-creds container will exit 1, if they complete the container will exit 0 thus getting around the sidecar problem.

To make this work you need to add the pod name and namespaces as env vars to the vault-creds container.

```
env:
- name: NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
- name: POD_NAME
  valueFrom:
    fieldRef:
      fieldPath: metadata.name
```

Also ensure that the service account you use has permission to `GET` pods in its own namespace.

## License

```
Copyright 2017 uSwitch

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
