# Captura Wireshark: plano frente a TLS

Esta demostración requiere ejecutar el servidor y el cliente en equipos que
puedan comunicarse por la IP y el puerto elegidos. Los certificados deben
haberse generado previamente en `pki/out/`.

## Modo plano

En el equipo servidor:

```powershell
py -3 -m app.servidor --modo plano --host 0.0.0.0 --puerto 8443
```

En el equipo cliente, sustituir `192.0.2.10` por la IP real del servidor:

```powershell
py -3 -m app.cliente --modo plano --host 192.0.2.10 --puerto 8443 `
  --comando "LOGIN admin Admin123!" --comando "ECHO mensaje visible"
```

En Wireshark, seleccionar la interfaz correcta y usar el filtro:

```text
tcp.port == 8443
```

Seguir un paquete con **Analyze > Follow > TCP Stream**. El texto `LOGIN`,
`Admin123!` y `mensaje visible` debe ser legible en la captura.

## Modo TLS

Detener el servidor plano y arrancar TLS con el certificado y la llave:

```powershell
py -3 -m app.servidor --modo tls --host 0.0.0.0 --puerto 8443 `
  --cert pki/out/servidor.crt --key pki/out/servidor.key.pem
```

Conectar desde el cliente usando el mismo nombre o IP incluido en el SAN:

```powershell
py -3 -m app.cliente --modo tls --host 192.0.2.10 --puerto 8443 `
  --ca pki/out/ca.crt --verbose --comando "LOGIN admin Admin123!" `
  --comando "ECHO mensaje cifrado"
```

El filtro de Wireshark es el mismo. Ahora se observan `Client Hello`,
`Server Hello` y registros TLS, pero no aparecen los comandos ni sus
contraseñas al seguir el flujo TCP. El campo **Info** permite verificar que
la negociación usa TLS 1.2 o superior.

Para probar el rechazo de los cuatro certificados de Fase 2, sustituir
temporalmente el valor de `--cert` por
`invalidos/invalido_autofirmado.crt`, `invalidos/invalido_otra_ca.crt`,
`invalidos/invalido_expirado.crt` o `invalidos/invalido_hostname.crt`,
usando la llave privada correspondiente al conjunto
de prueba. El cliente debe terminar con `TLS rechazado:` y mostrar el mensaje
de verificación de OpenSSL (cadena no confiable, expiración o hostname).
