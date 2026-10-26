# IoT Security - Practical Work 1 (TP1)
## Advanced Digital Signature Scheme: Ring Signature (AOS on Ed25519)

This repository contains the complete implementation, test suites, performance benchmarks, and IoT simulation for **TP1** of the IoT Security & Cybersecurity module.

---

### Team & Deliverables
* **Variant:** Abe-Ohkubo-Suzuki (AOS) Ring Signature built on top of the Ed25519 elliptic curve group[cite: 2].
* **IoT Scenario:** A set of sensors belongs to a trusted ring; a sensor signs a reading so the gateway verifies it came from *some* member of the ring without revealing *which* member signed[cite: 2].

---

### Project Structure
- `ed25519_core.py`: Pure-Python implementation of Ed25519 curve operations (point addition, scalar multiplication, hashing).
- `ring_signature.py`: Implementation of KeyGen, Ring Sign (`ring_sign`), and Ring Verify (`ring_verify`).
- `test_correctness.py`: Pytest suite verifying correctness, tampering, wrong rings, unforgeability, and anonymity structure.
- `test_properties_and_benchmark.py`: Anonymity property verification and performance benchmarking ($n = 2, 8, 32, 128$).
- `iot_mqtt_demo.py`: IoT simulation demonstrating an anonymous sensor publishing signed readings to a gateway.

---

### How to Reproduce Results

1. **Install Dependencies:**
   ```bash
   pip install pytest numpy