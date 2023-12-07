#!/usr/bin/env python 

# python 3.8

import random
import time
import json
import threading
from paho.mqtt import client as mqtt_client


broker = '101.227.231.138'
port = 18080
topic = "devices/1931818307682306/query"
# generate client ID with pub prefix randomly
client_id = f'python-mqtt-{random.randint(0, 1000)}'


def connect_mqtt():
    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print("Connected to MQTT Broker!")
        else:
            print("Failed to connect, return code %d\n", rc)

    client = mqtt_client.Client(client_id)
    client.tls_set(ca_certs='./conf/zxykey.cer')
    client.tls_insecure_set(True)
    client.on_connect = on_connect
    client.connect(broker, port)
    return client


def publish(client):
    msg_count = 0
    msg = {
            "code": 1008,
            "sequence": "12345",
            "deviceId": "1931818307682306",
            "mac": "14EB088CD2AB",
            "time": 1361542433,
            "query": [{
                "name": "ssidMesList"
            }]
        }

    object_json = json.dumps(msg, indent=4)

    for i in range(100):
        time.sleep(1)
        result = client.publish(topic, object_json.encode("utf-8"))
        # result: [0, 1]
        status = result[0]
        if status == 0:
            print(f"Send `{msg}` to topic `{topic}`")
        else:
            print(f"Failed to send message to topic {topic}")
        msg_count += 1


def run():
    client = connect_mqtt()
    client.loop_start()

    num_threads = 20
    threads = []

    for i in range(num_threads):
        thread = threading.Thread(target=publish, args=(client, ))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()


if __name__ == '__main__':
    run()

