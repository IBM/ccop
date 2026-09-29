# Confidential Operations (ccop)

ccop is a command-line tool that enables security-sensitive Kubernetes operations within a Confidential Containers (CoCo) deployment. The initial release supports `kubectl exec`. It wraps `exec` command arguments in a Hybrid Public Key Encryption (HPKE) Auth-mode envelope using a user's private key and a public key provisioned to the workload at startup.  This cryptographically binds the user's identity to the `exec` request and locks command decryption and verification to the workload with the corresponding credential.

Additionally, per-session stream keys are derived from the same HPKE context and are used to encrypt all stdin/stdout/stderr traffic end-to-end, so neither the host OS, the container runtime, nor the Kubernetes control plane can observe or tamper with operational data.

## Assumptions
1. The Kubernetes cluster has a container runtime, e.g., `kata-qemu-snp-ccop`, with `agent-policy` and `cc-op` features enabled.
   > [!IMPORTANT]
   > A key requirement is that the runtime's root image is compiled with both `AGENT_POLICY=yes` and `CC_OP=yes` options enabled. 
 <!-- - k8s cluster configured with the cc-op enabled runtime class is accessible. -->
<!--
 Follow the instructions for [building a customized CoCo image supporting `cc-op`](https://github.ibm.com/rvaldez/coco/blob/main/ROOTIMAGE.md). 
--> 
2. Trustee is deployed running a [Key Broker Service](https://github.com/salmanyam/trustee/blob/splitapi-plugin/kbs/docs/plugins/secretprov.md) implementing the `SecretProv` Plugin. This plugin dynamically generates cryptographic credentials for confidential VMs.

## Getting Started
- Build ccop tool
- Generate key pairs: one for the **user** 

#### Clone and Build the tool
- Retrieve tool, change directory, and build
   ```
   $ git clone git@github.com:IBM/ccop.git
   $ cd ccop
   $ go build
   ```

#### Generate a User Key
- Create an EC public and private key pair
  ```
  $ openssl ecparam -name prime256v1 -genkey -noout -out key.priv
  $ openssl ec -in key.priv -pubout -out key.pub
  ```
-  Write a certificate configuration 
   ```
   $ tee > openssl.cnf <<EOF
   # Edit generic configuration
   [ req ]
   distinguished_name = dn
   x509_extensions = v3_req
   prompt = no

   [ dn ]
   C = US
   ST = NY
   L = New York City
   O = Development
   CN = John Doe
   #emailAddress = johndoe@foobar.com

   [ v3_req ]
   basicConstraints = CA:FALSE
   keyUsage = critical, digitalSignature
   subjectAltName = @alt_names

   [ alt_names ]
   DNS.1 = John Doe
   email.1 = johndoe@foobar.com
   EOF
   ```
-  Build a self-signed certificate of the public key
   ```
   $ openssl req -new -key key.priv -out cert.csr -config openssl.cnf
   $ openssl x509 -req -in cert.csr -signkey key.priv -out cert.crt -days 365 \
	-extensions v3_req -extfile openssl.cnf

   ```

## Test kubectl exec use case authenticating command arguments
- Save the user certificate in shell variable
   ```
   $ CERTDATA=$(cat cert.crt)
   ```

- Set shell variables to KBS URL and admin private key file (PEM)
   ```
   $ export KBS_URL=<KBS_SERVER_URL>
   $ export KBS_PRIVATE_KEY=/path/to/kbs_private.key
   ```

- Create initdata with an agent policy that blocks all exec operations and a ccop config file (ccop.toml) containing the user's public certificate (`auth_cert`). This embedded config file enables cc-op for the workload.

   ```
   $ tee > initdata.toml <<EOF
   version = "0.1.0"
   algorithm = "sha256"
   [data]
   "policy.rego" = '''
   package agent_policy

   default AddARPNeighborsRequest := true
   default AddSwapRequest := true
   default CloseStdinRequest := true
   default CopyFileRequest := true
   default CreateContainerRequest := true
   default CreateSandboxRequest := true
   default DestroySandboxRequest := true

   # Block exec by default
   default ExecProcessRequest := false

   default GetMetricsRequest := true
   default GetOOMEventRequest := true
   default GuestDetailsRequest := true
   default ListInterfacesRequest := true
   default ListRoutesRequest := true
   default MemHotplugByProbeRequest := true
   default OnlineCPUMemRequest := true
   default PauseContainerRequest := true
   default PullImageRequest := true
   default ReadStreamRequest := true
   default RemoveContainerRequest := true
   default RemoveStaleVirtiofsShareMountsRequest := true
   default ReseedRandomDevRequest := true
   default ResumeContainerRequest := true
   default SetGuestDateTimeRequest := true
   default SetPolicyRequest := true
   default SignalProcessRequest := true
   default StartContainerRequest := true
   default StartTracingRequest := true
   default StatsContainerRequest := true
   default StopTracingRequest := true
   default TtyWinResizeRequest := true
   default UpdateContainerRequest := true
   default UpdateEphemeralMountsRequest := true
   default UpdateInterfaceRequest := true
   default UpdateRoutesRequest := true
   default WaitProcessRequest := true
   default WriteStreamRequest := true
   '''

   "ccop.toml" = '''
   auth_cert ="""
   ${CERTDATA}
   """
   '''

   "aa.toml" = '''
   [token_configs]
   [token_configs.kbs]
   url = "${KBS_URL}"
   '''

   "cdh.toml" = '''
   [kbc]
   name = "cc_kbc"
   url = "${KBS_URL}"
   '''
   EOF
   ```

- Embed base64 encoding of initdata in pod configuration
   ```
   $ INITDATA=$(cat initdata.toml | gzip | base64 -w0)

   $ tee > pod-busybox-exec.yaml <<EOF
   apiVersion: v1
   kind: Pod
   metadata:
     name: pod-busybox-exec
     annotations:
       io.containerd.cri.runtime-handler: kata-qemu-snp-ccop
       io.katacontainers.config.hypervisor.cc_init_data: ${INITDATA}
   spec:
     runtimeClassName: kata-qemu-snp-ccop
     containers:
        - name: busybox 
          image: quay.io/prometheus/busybox:latest 
          imagePullPolicy: Always
          command: ["sleep", "infinity"]
     restartPolicy: Never
   EOF
   ```

- Deploy workload
   ```
  $ kubectl apply -f pod-busybox-exec.yaml
   ```

-  Display running pod(s)
   ```
   $ kubectl get pods
   NAME               READY   STATUS    RESTARTS       AGE
   pod-busybox-exec   1/1     Running   0              16s
   ...
   ```
   > **Note:** the create pod sandbox operation fails if the pod is unable to retrieve
   > its credential from Trustee.

-  Execute the original `kubectl exec`; it fails
   ```
   $ kubectl exec pod-busybox-exec -- ls -C /
      error: Internal error occurred: Internal error occurred: error executing command in container: failed to exec in container: failed to start exec "3fdc43d613a7096822eea349691ccb938c7290ccb40267291c05e9a009d15478": cannot enter container 6631f6b1c127d85eb49440e2ddfa75a3eb499264ff7d1c1209daca1f3bc29f11, with err rpc error: code = Internal desc = Error: missing arguments: --payload

   Stack backtrace:
      0: ...
   ```

-  Fetch the pod's public key certificate from Trustee (KBS) and save in `./receiver.crt`

   ```
   $ ccop fetch --url "${KBS_URL}" --auth-key "${KBS_PRIVATE_KEY}" \
   --namespace default --pod pod-busybox-exec \
   secret_name=ccop_p256 secret_type=p256 --out ./receiver.crt
   ```

- Run `ccop exec`, specifying `--privkey` for the user's private key; and  `--pubkeycert` for the pod's public certificate; it successfully executes
   ```
   $ ccop exec pod-busybox-exec --privkey ./key.priv --pubkeycert ./receiver.crt -- ls -C /
   bin   dev   etc   home  lib   proc  root  sys   tmp   usr   var
   ```

## ccop Configuration
The `ccop config` command manages and displays the ccop environment. It always requires an option (`--auth-key`, `-c`, or `-l` ).

#### Generate a configuration: 
   ```
   $ ccop config -c
   ```

- Creates the `~/.ccop/` directory in the user home directory, containing a `config.toml` file and a `cache` sub-directory, containing artifacts from running ccop confidential workloads, e.g., the pod's `receiver.crt`.

- Add paths to the user EC key pair in `config.toml`. This avoids specifying `--privkey` on every command:
   ```
   $ vim ~/.ccop/config.toml
   UserPublicKeyCert = "/path/to/user/publickeycert"
   UserPrivateKey = "/path/to/user/privatekey"
   ```

#### Retrieve mypod's artifacts from Trustee (KBS) and save in cache directory:
   ```
   $ ccop config mypod --auth-key "${KBS_PRIVATE_KEY}"
   ```
- Extracts KBS's URL from the running pod's initdata.
- Retrieves artifacts, including the public key certificate associated with sandbox environment ... 
- This avoids specifying `--pubkeycert` on every command.

With both the key paths and the certificate cached, all key flags can be omitted:
```bash
$ ccop exec pod-busybox-exec -- ls -C /
bin   dev   etc   home  lib   proc  root  sys   tmp   usr   var
```

#### Report ccop status on all running pods:
   ```
   $ ccop config -l

   === Pod: default/busybox ===

   === Pod: default/pod-busybox-exec ===
	algorithm: sha256
	digest: 2iu8vLDEocN72nfOKvfA6fA3BBhgtC7KcdxKZsDcYNc=
	ccop.toml: defined
	ccop.toml.auth_cert: set
	cdh.toml: defined
	cdh.toml.kbs: cc_kbc
	cdh.toml.url: http://1.2.3.4:8080

   === Pod: default/busybox-noccop-nexec ===
	algorithm: sha256
	digest: 0zH/DXa2cy0mD/nsSgHTcXToHn0vhkWhHDeXkrPFVRc=
	initdata ccop.toml: not found
   ...
   ```

#### Check a specific pod's ccop status: 
   ```
   $ ccop config -l pod-busybox-exec
   pod-busybox-exec is ccop enabled
   ```

Checks whether a pod's initdata contains a `ccop.toml` with an `auth_cert`.

## Future Work 
- Support for other command-specific options: `-f`, `-q`, and `--pod-running-timeout`
- Support for overriding any command inherited option 
- Support for `cp`, `attach`, and `logs` is planned for follow-on release(s)

