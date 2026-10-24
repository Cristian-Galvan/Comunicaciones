# VPN de acceso remoto frente a VPN sitio a sitio

| Aspecto | Acceso remoto | Sitio a sitio |
|---|---|---|
| Quién se autentica | Cada usuario contra AAA al conectarse | Los gateways mediante una clave precompartida |
| Qué se protege | Tráfico del cliente conectado hacia recursos autorizados | Tráfico entre `10.1.0.0/24` y `10.2.0.0/24` |
| Granularidad de acceso | Por sesión, rol y recurso; se revisa cada solicitud | Por rutas/CIDR: solo las dos redes configuradas |
| Persistencia | Sesión con token, IP virtual y expiración | Túnel permanente mientras ambos gateways estén enlazados |

Ambas implementaciones son simulaciones didácticas: reutilizan ESP con
AES-GCM del módulo `ipsec`, pero no implementan IKE, negociación de SA,
rekey ni interfaces de red reales.
