# Vault Creds

Program (and Docker container) to be run as a sidecar to your application- requesting dynamic database credentials that will be leased while the application is active or requests certificate for the designated ttl

It implements authentication according to [Vault's Kubernetes Authentication flow](https://kubernetes.io/docs/admin/authentication/).

## Usage

This project is to be deployed in a Pod alongside the main application. When `vault-creds` starts it will request credentials or a certifcate at the path specified and continually renew their lease.

### Credentials Example

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

### Certificate Example

```
$ ./bin/vaultcreds \
  --get-certificate \
  --common-name="commonname" \
  --ttl="2m" \
  --ca-cert=~/.vaultca \
  --token-file=/var/run/secrets/kubernetes.io/serviceaccount/token \
  --login-path=kubernetes/cluster/login \
  --auth-role=service_account_role \
  --template=sample.certificate.yml \
  --secret-path=database/creds/database_role
INFO[0000] authenticated                                 policies="[default service_account_role]"
INFO[0000] requesting certificate
-----BEGIN CERTIFICATE-----
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
-----END CERTIFICATE-----INFO[0000] renewing certficate every 24h
```

The template is applied to the latest credentials and written to `--out` (normally this would be a shared mount for the other containers read).

## Init Mode

If you run the container with the `--init` flag it will generate the database credentials and then exit allowing it to be used as an Init Container.
Vault-creds will also write out the lease and auth info to a file in the same directory as your database credentials, if a new Vault-creds container starts up it can read these and use them to renew your lease.
This means that you can have an init container generate your creds and then have a sidecar renew your credentials for you. Thus ensuring the credentials exist before your app starts up.

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
