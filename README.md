# secure_tunnel

Учебный/исследовательский инструмент приватной передачи данных.

## Что реализовано

- Шифрование ChaCha20-Poly1305 поверх WebSocket
- X25519 ECDH для согласования ключа сессии
- Фрейминг с рандомизированным паддингом
- Onion-маршрут: Client → Node1 → ExitNode
- Dummy-трафик (валидные onion-пакеты, неотличимые от реальных)
- Анонимизированные логи (без IP, без содержимого)
- Интерфейс HybridKeyExchange под PQ-KEM

## Установка

```bash
pip install -r requirements.txt
```

## Запуск onion-маршрута

Откройте 3 терминала:

**Терминал 1 — Exit node:**
```bash
python -m secure_tunnel.exit_node
```

**Терминал 2 — Node1:**
```bash
python -m secure_tunnel.node1
```

**Терминал 3 — Client:**
```bash
python -m secure_tunnel.onion_client
```

При первом запуске в папке `secure_tunnel_keys/` создадутся ключи узлов.

## Структура проекта

```
secure_tunnel/
  secure_tunnel/
    crypto.py          # AEAD шифрование + KDF
    framing.py         # фрейминг с паддингом
    protocol.py        # типы сообщений, pack/unpack
    key_exchange.py    # X25519, PQ-KEM stub, HybridKeyExchange
    keyring.py         # хранение статических ключей узлов
    config.py          # маршрут и параметры dummy-трафика
    onion.py           # сборка/снятие onion-слоёв
    dummy_scheduler.py # генератор dummy-трафика
    node1.py           # промежуточный узел
    exit_node.py       # конечный узел
    onion_client.py    # клиент
    logging/
      anon_logger.py   # анонимизированные логи
  logs/                # лог-файлы
  secure_tunnel_keys/  # ключи узлов
  tests/
  requirements.txt
```

## Подключение реального PQ-KEM

В `key_exchange.py` замените `PQKeyExchangeStub` на реальную реализацию, например через `liboqs-python`:

```python
import oqs

class KyberKeyExchange(KeyExchange):
    def generate_keypair(self):
        kem = oqs.KeyEncapsulation("Kyber512")
        pub = kem.generate_keypair()
        return kem, pub

    def derive_shared(self, kem, peer_pub):
        ciphertext, shared = kem.encap_secret(peer_pub)
        return shared
```

## Логи

Логи пишутся в `logs/anon.log` в формате JSON (без IP и содержимого):
```json
{"ts": 1700000000.123, "hop": "node1", "sid": 12345678, "type": 1, "len": 512, "dir": "in"}
```
