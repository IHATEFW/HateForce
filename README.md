# HateForce

<img width="1127" height="556" alt="hateforce2" src="https://github.com/user-attachments/assets/3598314b-09aa-4d97-ad3f-bb7307d4a155" />

He creado **HateForce**, una herramienta para hacer fuerza bruta a la contraseña de
`su` en la propia máquina. La idea es simple: cuando ya tienes una shell sin
privilegios (en un CTF o en un pentest autorizado) y quieres escalar a otro usuario,
le pasas un diccionario y va probando contraseñas hasta dar con la buena.

Solo trabaja contra el `su` **local**. No toca servicios remotos ni nada por el estilo.

## Qué trae

- Banner con colores y una barra de progreso en vivo (porcentaje, velocidad, ETA y la contraseña que está probando).
- Funciona de verdad con `su` usando una terminal real por detrás, así que no falla como los típicos scripts que hacen `echo contraseña | su`.
- Lee el resultado real de `su`, no se inventa aciertos.
- Un modo `--fast` para ir más rápido, que además te avisa si algún intento quedó en duda.
- No necesita instalar nada: solo Python 3.

## Cómo se usa

```bash
# Fuerza bruta a root con rockyou
python3 hateforce.py -u root -w /usr/share/wordlists/rockyou.txt

# Modo rápido (más veloz, pero en máquinas lentas podría saltarse la clave buena)
python3 hateforce.py -u root -w rockyou.txt --fast

# Otro usuario, con tiempo de espera y pausa entre intentos
python3 hateforce.py -u victima -w passwords.txt -t 3 -d 0.2
```

### Opciones

| Opción | Para qué sirve |
|--------|----------------|
| `-u`, `--user` | Usuario objetivo (por defecto: `root`) |
| `-w`, `--wordlist` | Ruta al diccionario de contraseñas (obligatorio) |
| `-t`, `--timeout` | Segundos de espera por intento (por defecto: `5`) |
| `-d`, `--delay` | Pausa entre intentos en segundos (por defecto: `0`) |
| `--fast` | Espera corta de `0.4s`; más rápido, pero en máquinas lentas puede saltarse la clave |
| `--no-color` | Desactiva los colores |

## Un par de cosas a tener en cuenta

Hacer fuerza bruta al `su` local es lento por naturaleza: Linux mete una pausa a
propósito cada vez que fallas la contraseña (un par de segundos), justamente para
ponérselo difícil a herramientas como esta. La contraseña correcta, en cambio, entra
al instante. No es un problema de la herramienta, es cómo funciona el sistema.

El modo `--fast` aprovecha eso para ir más rápido, y al final te dice cuántos intentos
quedaron en duda por si quieres repetirlos sin `--fast`.

## Aviso

Úsala solo donde tengas permiso: tus propias máquinas, laboratorios de CTF o pentests
autorizados. El uso que le des es responsabilidad tuya.

---

By **IHATEFW**
