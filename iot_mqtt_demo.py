import time
from ring_signature import keygen, ring_sign, ring_verify

def run_iot_demo():
    print("[*] Initializing IoT Ring Signature Local Simulation Demo...")
    
    # 1. إعداد حلقة من 10 مستشعرات (Sensors)
    n = 10
    keys = [keygen() for _ in range(n)]
    sk_list = [k[0] for k in keys]
    pk_list = [k[1] for k in keys]
    
    print(f"[+] Created a ring of {n} IoT sensors.")

    # محاكاة وسيط الرسائل (Broker Queue)
    broker_queue = []

    # إعداد البوابة (Gateway Subscriber)
    def gateway_receive(topic, message_bytes, signature):
        print(f"\n[Gateway] [MQTT Broker] Message received on topic '{topic}':")
        try:
            print(f"   -> Sensor Reading: {message_bytes.decode('utf-8')}")
            
            # التحقق من التوقيع بواسطة البوابة باستخدام مفاتيح الحلقة العامة
            is_valid = ring_verify(message_bytes, pk_list, signature)
            
            if is_valid:
                print("[Gateway] [SUCCESS] Ring Signature VERIFIED! (Authentic IoT reading from an anonymous ring member).")
            else:
                print("[Gateway] [FAILED] Ring Signature verification failed!")
                
        except Exception as e:
            print(f"[Gateway] Error processing message: {e}")

    # 2. محاكاة قيام أحد المستشعرات (مثلاً المستشعر رقم 5) بإرسال قراءة موقعة
    sensor_idx = 5
    reading_data = {
        "sensor_id": sensor_idx, 
        "temperature": 24.8, 
        "humidity": 60.2, 
        "timestamp": time.time()
    }
    message_bytes = str(reading_data).encode('utf-8')
    
    print(f"[*] Sensor #{sensor_idx} is signing its reading...")
    signature = ring_sign(message_bytes, pk_list, sensor_idx, sk_list[sensor_idx])
    
    topic = "iot/security/tp1/sensors"
    print(f"[*] Publishing payload to MQTT topic: {topic}")
    
    # محاكاة إرسال الرسالة عبر البروكر (تمرير الكائنات مباشرة بأمان)
    broker_queue.append((topic, message_bytes, signature))
    
    # البوابة تستمع للرسائل وتقوم بمعالجتها
    time.sleep(1)
    print("[*] Gateway processing incoming queue...")
    for t, msg_b, sig in broker_queue:
        gateway_receive(t, msg_b, sig)
        
    print("\n[+] IoT MQTT Simulation Demo completed successfully!\n")

if __name__ == "__main__":
    run_iot_demo()