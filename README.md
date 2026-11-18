}
```

---

## Integración con Burp Suite

Con `--burp` (o `--proxy http://127.0.0.1:8080`) todas las peticiones pasan por
Burp, de modo que tu plugin de reporte las captura. Notas:

- `CONNECT` se **omite automáticamente** cuando hay proxy: el proxy responde él
  mismo `200 Connection established`, lo que sería un falso positivo. Para
  probar `CONNECT` contra el servidor, lánzalo **sin** proxy.
- Para destinos HTTPS, `--burp` desactiva la verificación TLS (Burp usa su
  propia CA).

---

## Aviso legal

Úsala **únicamente** contra sistemas para los que tengas **autorización
explícita**. El uso contra sistemas de terceros sin permiso es ilegal. El autor
no se responsabiliza del mal uso de esta herramienta.
                                                              307,20      Final
