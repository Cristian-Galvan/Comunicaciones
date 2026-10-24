# PKI de demostración

Los scripts requieren Bash y OpenSSL CLI. Los parámetros del servidor son el
nombre DNS y la dirección IP que aparecerán en el SAN:

```bash
./pki/01_crear_ca.sh
./pki/02_crear_cert_servidor.sh servidor.ejemplo.test 192.0.2.10
./pki/03_crear_certs_invalidos.sh servidor.ejemplo.test 192.0.2.10
./pki/verificar_pki.sh servidor.ejemplo.test 192.0.2.10
```

Todo el material generado se guarda en `pki/out/`, que está excluido de Git.
Las llaves y certificados de prueba inválidos se guardan juntos en
`pki/out/invalidos/` y nunca deben copiarse al cliente.
La CA es RSA de 4096 bits y tiene una vigencia de 10 años; el certificado del
servidor tiene una vigencia de un año, `CA:FALSE`, `serverAuth` y SAN DNS/IP.
Los scripts son idempotentes: no regeneran un conjunto completo existente ni
continúan cuando detectan un conjunto parcial.

La verificación de hostname requiere `-verify_hostname`: el comando básico
`openssl verify -CAfile` comprueba la cadena de confianza, pero por diseño no
valida el nombre DNS.
