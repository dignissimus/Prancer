import binascii
import socket

REQUEST = "0001"
RESPONSE = "0002"


class Device:
    def __init__(self, ip, mac=None):
        self.mac = mac
        self.ip = ip


class Prancer:
    @staticmethod
    def encode_ip(ip) -> str:
        """

        Args (str): The dor separated IP address to encode
            ip:

        Returns: a hex-string version to be sent in an ARP request or response

        """
        return ''.join(map(lambda number: '{0:02x}'.format(int(number)), ip.split(".")))

    @staticmethod
    def form_payload(receiver, sender, requested, payload_type) -> bytearray:

        stream = [receiver.mac, sender.mac, "0806000108000604", payload_type]
        if payload_type == REQUEST:
            stream.append(sender.mac)
            stream.append(Prancer.encode_ip(sender.ip))
            stream.append("00" * 6)  # 000000000000
            stream.append(Prancer.encode_ip(requested.ip))

        if payload_type == RESPONSE:
            stream.append(requested.mac)
            stream.append(Prancer.encode_ip(requested.ip))
            stream.append(receiver.mac)
            stream.append(Prancer.encode_ip(receiver.ip))

        return bytearray.fromhex(''.join(map(lambda packet: packet.replace(" ", "").replace(":", ""), stream)))

    @staticmethod
    def form_response(receiver, sender, requested) -> bytearray:
        """

        Args:
            receiver (Device): The receiver device, the intended receiver for ths message
            sender (Device): The sender device, the sender of the message
            requested (Device): The requested device, the device whose MAC address is being requested

        Returns: A ARP request payload in the form of a bytearray

        """
        return Prancer.form_payload(receiver, sender, requested, RESPONSE)

    @staticmethod
    def form_request(receiver, sender, requested) -> bytearray:
        """

        Args:
            receiver (Device): The receiver device, the intended receiver for ths message
            sender (Device): The sender device, the sender of the message
            requested (Device): The requested device, the device whose MAC address is being requested

        Returns: A ARP request payload in the form of a bytearray

        """
        return Prancer.form_payload(receiver, sender, requested, REQUEST)

    def __init__(self, interface):
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)  # creates the socket object
        # binds the socket so that we can broadcast out ARP responses and requests
        self.socket.bind((interface,
                          socket.SOCK_RAW))

    def respond(self, receiver_ip, receiver_mac, sender_ip, sender_mac, requested_ip, requested_mac):
        """

        Args:
            receiver_ip: The IP address belonging to the intended receiver
            receiver_mac: The MAC address belonging to the intended receiver
            sender_ip: The IP address belonging to the message sender
            sender_mac: The MAC address belonging to the message sender
            requested_ip: The IP address belonging to the device whose MAC address was requested
            requested_mac: The MAC address belonging to the device whose MAC address was requested

        Returns: Nothing

        """
        sender, receiver, requested = Device(receiver_ip, receiver_mac), \
                                      Device(sender_ip, sender_mac), \
                                      Device(requested_ip, requested_mac)

        payload = Prancer.form_response(sender, receiver, requested)
        print(payload)
        print(binascii.hexlify(payload))
        self.socket.send(payload)

    def request(self, receiver_ip, receiver_mac, sender_ip, sender_mac, requested_ip, requested_mac):
        """

        Args:
            receiver_ip: The IP address belonging to the intended receiver
            receiver_mac: The MAC address belonging to the intended receiver
            sender_ip: The IP address belonging to the message sender
            sender_mac: The MAC address belonging to the message sender
            requested_ip: The IP address belonging to the device whose MAC address was requested
            requested_mac: The MAC address belonging to the device whose MAC address was requested

        Returns: Nothing

        """
        sender, receiver, requested = \
            Device(receiver_mac, receiver_mac), \
            Device(sender_ip, sender_mac), \
            Device(requested_ip, requested_mac)

        payload = Prancer.form_request(sender, receiver, requested)
        print(payload)
        print(binascii.hexlify(payload))
        self.socket.send(payload)
