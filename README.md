# SGX-RA-TLS client

This project aims at providing a sample code of a client able to retrieve, validate, and then trust a certificate of a server that uses the SGX-RA-TLS protocol.
To run this client, you need to first setup your project by editing the `configs.conf` file.

After setting up your project, you can try this client by running
```bash
docker build -t sgx-ra-tls-client .
docker run --rm sgx-ra-tls-client
```