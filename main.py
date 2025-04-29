from client import Client

peer = Client()
peer.listen("localhost", 5001)
import time; time.sleep(2)
peer.receive_file("test.pdf")
peer.close()
