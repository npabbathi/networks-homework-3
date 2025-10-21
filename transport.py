import argparse
import json
from typing import Dict, List, Optional, Tuple
import random
import socket
import math

# Note: In this starter code, we annotate types where
# appropriate. While it is optional, both in python and for this
# course, we recommend it since it makes programming easier.

# The maximum size of the data contained within one packet
payload_size = 1200
# The maximum size of a packet including all the JSON formatting
packet_size = 1500


class Receiver:
    # we need to send this later !!!
    range_to_data: Dict[Tuple[int, int], str]
    start_to_end: Dict[int, int]
    # we can only send data from 0 to the end of the first range, [0, end] is all the data we've sent so far in a str
    end: int

    # list of all ranges we have so far
    # gack for mr mike scott
    gack: List[Tuple[int, int]]

    def __init__(self):
        # TODO: Initialize any variables you want here, like the receive buffer
        self.range_to_data = {}
        self.start_to_end = {}
        self.end = 0
        self.gack = []

    def data_packet(self, seq_range: Tuple[int, int], data: str) -> Tuple[List[Tuple[int, int]], str]:
        '''This function is called whenever a data packet is
        received. `seq_range` is the range of sequence numbers
        received: It contains two numbers: the starting sequence
        number (inclusive) and ending sequence number (exclusive) of
        the data received. `data` is a binary string of length
        `seq_range[1] - seq_range[0]` representing the data.

        It should output the list of sequence number ranges to
        acknowledge and any data that is ready to be sent to the
        application. Note, data must be sent to the application
        _reliably_ and _in order_ of the sequence numbers. This means
        that if bytes in sequence numbers 0-10000 and 11000-15000 have
        been received, only 0-10000 must be sent to the application,
        since if we send the latter bytes, we will not be able to send
        bytes 10000-11000 in order when they arrive. The solution
        layer must hide hide all packet reordering and loss.

        The ultimate behavior of the program should be that the data
        sent by the sender should be stored exactly in the same order
        at the receiver in a file in the same directory. No gaps, no
        reordering. You may assume that our test cases only ever send
        printable ASCII characters (letters, numbers, punctuation,
        newline etc), so that terminal output can be used to debug the
        program.

        '''

        # merge the stupid intervals from leetcode
        self.gack.append(seq_range)
        self.start_to_end[seq_range[0]] = seq_range[1]
        self.range_to_data[seq_range] = data

        merged = []
        self.gack.sort(key=lambda x: x[0])
        new_range_to_data = {}
        new_start_to_end = {}

        prev = self.gack[0]
        prev_data = self.range_to_data[prev]

        for interval in self.gack[1:]:
            # we are merging
            if interval[0] <= prev[1]:
                # update the list
                prev = (prev[0], max(prev[1], interval[1]))
                prev_data += self.range_to_data[interval]
            else:
                new_range_to_data[prev] = prev_data
                new_start_to_end[prev[0]] = prev[1]
                merged.append(prev)
                # start of the new interval
                prev = interval
                prev_data = self.range_to_data[prev]
        
        new_range_to_data[prev] = prev_data
        new_start_to_end[prev[0]] = prev[1]
        merged.append(prev)

        # update instance variables
        self.gack = merged
        self.range_to_data = new_range_to_data
        self.start_to_end = new_start_to_end

        sending_data = ""
        for start, stop in self.gack:
            if start == self.end:
                sending_data += self.range_to_data[(start, stop)]
                self.end = stop

        return (self.gack, sending_data)

    def finish(self):
        '''Called when the sender sends the `fin` packet. You don't need to do
        anything in particular here. You can use it to check that all
        data has already been sent to the application at this
        point. If not, there is a bug in the code. A real solution
        stack will deallocate the receive buffer. Note, this may not
        be called if the fin packet from the sender is locked. You can
        read up on "TCP connection termination" to know more about how
        TCP handles this.

        '''
        if (len(self.gack) > 1):
            print("SOMETHING IS WRONG!!!!!!!!!!!!!!!")
            print("self.gack:", self.gack)

 # statuses used in packet_to_status
UNSENT = 0
SENT = 1
ACK = 2
LOST = 3

class Sender:
    # maps the range of squence numbers to its current state 
    packet_to_status: Dict[int, int]
    packet_to_range: Dict[int, Tuple[int, int]]

    # in terms of number of packets
    total_packets: int

    # in terms of bytes
    data_length: int

    def __init__(self, data_len: int):
        '''`data_len` is the length of the data we want to send. A real
        solution will not force the application to pre-commit to the
        length of data, but we are ok with it.

        '''
        self.data_length = data_len
        self.total_packets = math.ceil(data_len / payload_size)

        self.packet_to_status = {}
        self.packet_to_range = {}
        for i in range(self.total_packets):
            self.packet_to_status[i] = UNSENT
            self.packet_to_range[i] = (i * payload_size, (i + 1) * payload_size)

        self.packet_to_range[self.total_packets - 1] = ((self.total_packets - 1) * payload_size, data_len)

    def timeout(self):
        '''Called when the sender times out.'''
        # TODO: Read the relevant code in `start_sender` to figure out
        # what you should do here

        for key in self.packet_to_status:
            if self.packet_to_status[key] == SENT:
                # packet has not been ack so it mustve been lost
                self.packet_to_status[key] = LOST

    def ack_packet(self, sacks: List[Tuple[int, int]], packet_id: int) -> int:
        '''Called every time we get an acknowledgment. The argument is a list
        of ranges of bytes that have been ACKed. Returns the number of
        payload bytes new that are no longer in flight, either because
        the packet has been acked (measured by the unique ID) or it
        has been assumed to be lost because of dupACKs. Note, this
        number is incremental. For example, if one 100-byte packet is
        ACKed and another 500-byte is assumed lost, we will return
        600, even if 1000s of bytes have been ACKed before this.

        '''
        inflight = 0

        for ack in sacks:
            start = ack[0]
            end = ack[1]
            for pid in self.packet_to_range:
                if self.packet_to_range[pid][0] >= start and self.packet_to_range[pid][1] <= end:
                    assert(self.packet_to_status[pid] != UNSENT)
                    if (self.packet_to_status[pid] != ACK):
                        self.packet_to_status[pid] = ACK
                        inflight += self.packet_to_range[pid][1] - self.packet_to_range[pid][0]

        return inflight

    def send(self, packet_id: int) -> Optional[Tuple[int, int]]:
        '''Called just before we are going to send a data packet. Should
        return the range of sequence numbers we should send. If there
        are no more bytes to send, returns a zero range (i.e. the two
        elements of the tuple are equal). Returns None if there are no
        more bytes to send, and _all_ bytes have been
        acknowledged. Note: The range should not be larger than
        `payload_size` or contain any bytes that have already been
        acknowledged

        '''

        total_ack = sum(1 for value in self.packet_to_status.values() if value == ACK)
        if (total_ack == self.total_packets):
            return None
        
        total_sent = sum(1 for value in self.packet_to_status.values() if value == UNSENT or value == LOST)
        if (total_sent == 0):
            return (0, 0)
        
        for pid in self.packet_to_status:
            if self.packet_to_status[pid] == LOST or self.packet_to_status[pid] == UNSENT:
                self.packet_to_status[pid] = SENT
                return self.packet_to_range[pid]


def start_receiver(ip: str, port: int):
    '''Starts a receiver thread. For each source address, we start a new
    `Receiver` class. When a `fin` packet is received, we call the
    `finish` function of that class.

    We start listening on the given IP address and port. By setting
    the IP address to be `0.0.0.0`, you can make it listen on all
    available interfaces. A network interface is typically a device
    connected to a computer that interfaces with the physical world to
    send/receive packets. The WiFi and ethernet cards on personal
    computers are examples of physical interfaces.

    Sometimes, when you start listening on a port and the program
    terminates incorrectly, it might not release the port
    immediately. It might take some time for the port to become
    available again, and you might get an error message saying that it
    could not bind to the desired port. In this case, just pick a
    different port. The old port will become available soon. Also,
    picking a port number below 1024 usually requires special
    permission from the OS. Pick a larger number. Numbers in the
    8000-9000 range are conventional.

    Virtual interfaces also exist. The most common one is `localhost',
    which has the default IP address of `127.0.0.1` (a universal
    constant across most machines). The Mahimahi network emulator also
    creates virtual interfaces that behave like real interfaces, but
    really only emulate a network link in software that shuttles
    packets between different virtual interfaces. Use `ifconfig` in a
    terminal to find out what interfaces exist in your machine or
    inside a Mahimahi shell

    '''

    receivers: Dict[str, Tuple[Receiver, Any]] = {}
    received_data = ''
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        server_socket.bind((ip, port))

        while True:
            print("======= Waiting =======")
            data, addr = server_socket.recvfrom(packet_size)
            if addr not in receivers:
                outfile = None  # open(f'rcvd-{addr[0]}-{addr[1]}', 'w')
                receivers[addr] = (Receiver(), outfile)

            received = json.loads(data.decode())
            if received["type"] == "data":
                # Format check. Real code will have much more
                # carefully designed checks to defend against
                # attacks. Can you think of ways to exploit this
                # transport layer and cause problems at the receiver?
                # This is just for fun. It is not required as part of
                # the assignment.
                assert type(received["seq"]) is list
                assert type(received["seq"][0]) is int and type(received["seq"][1]) is int
                assert type(received["payload"]) is str
                assert len(received["payload"]) <= payload_size

                # Deserialize the packet. Real transport layers use
                # more efficient and standardized ways of packing the
                # data. One option is to use protobufs (look it up)
                # instead of json. Protobufs can automatically design
                # a byte structure given the data structure. However,
                # for an internet standard, we usually want something
                # more custom and hand-designed.
                sacks, app_data = receivers[addr][0].data_packet(tuple(received["seq"]), received["payload"])
                # Note: we immediately write the data to file
                # receivers[addr][1].write(app_data)
                print(f"Received seq: {received['seq']}, id: {received['id']}, sending sacks: {sacks}")
                received_data += app_data

                # Send the ACK
                server_socket.sendto(json.dumps({"type": "ack", "sacks": sacks, "id": received["id"]}).encode(), addr)
            elif received["type"] == "fin":
                receivers[addr][0].finish()
                # Check if the file is received and send fin-ack
                if received_data:
                    print("received data (summary): ", received_data[:100], "...", len(received_data))
                    # print("received file is saved into: ", receivers[addr][1].name)
                    server_socket.sendto(json.dumps({"type": "fin"}).encode(), addr)
                    received_data = ''

                del receivers[addr]

            else:
                assert False


def start_sender(ip: str, port: int, data: str, recv_window: int, simloss: float, pkts_to_reorder: int):
    sender = Sender(len(data))

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
        # So we can receive messages
        client_socket.connect((ip, port))
        # When waiting for packets when we call receivefrom, we
        # shouldn't wait more than 500ms
        client_socket.settimeout(0.5)

        # Number of bytes that we think are inflight. We are only
        # including payload bytes here, which is different from how
        # TCP does things
        inflight = 0
        packet_id = 0
        wait = False
        send_buf = []

        while True:
            # Do we have enough room in recv_window to send an entire
            # packet?
            if inflight + packet_size < recv_window and not wait:
                seq = sender.send(packet_id)
                got_fin_ack = False
                if seq is None:
                    # We are done sending
                    # print("#######send_buf#########: ", len(send_buf))
                    if send_buf:
                        random.shuffle(send_buf)
                        for p in send_buf:
                            client_socket.send(p)
                        send_buf = []
                    client_socket.send('{"type": "fin"}'.encode())
                    try:
                        print("======= Final Waiting =======")
                        received = client_socket.recv(packet_size)
                        received = json.loads(received.decode())
                        if received["type"] == "ack":
                            client_socket.send('{"type": "fin"}'.encode())
                            continue
                        elif received["type"] == "fin":
                            print(f"Got FIN-ACK")
                            got_fin_ack = True
                            break
                    except socket.timeout:
                        inflight = 0
                        print("Timeout")
                        sender.timeout()
                        exit(1)
                    if got_fin_ack:
                        break
                    else:
                        continue

                elif seq[1] == seq[0]:
                    # No more packets to send until loss happens. Wait
                    wait = True
                    continue

                assert seq[1] - seq[0] <= payload_size
                assert seq[1] <= len(data)
                print(f"Sending seq: {seq}, id: {packet_id}")

                # Simulate random loss before sending packets
                if random.random() < simloss:
                    print("Dropped!")
                else:
                    pkt_str = json.dumps(
                        {"type": "data", "seq": seq, "id": packet_id, "payload": data[seq[0]:seq[1]]}
                    ).encode()
                    # pkts_to_reorder is a variable that bounds the maximum amount of reordering. To disable reordering, set to 1
                    if len(send_buf) < pkts_to_reorder:
                        send_buf += [pkt_str]

                    if len(send_buf) == pkts_to_reorder:
                        # Randomly shuffle send_buf
                        random.shuffle(send_buf)

                        for p in send_buf:
                            client_socket.send(p)
                        send_buf = []

                inflight += seq[1] - seq[0]
                packet_id += 1

            else:
                wait = False
                # Wait for ACKs
                try:
                    print("======= Waiting =======")
                    # ✅ added: accumulate partial packets in a buffer
                    buffer = ""
                    while True:
                        chunk = client_socket.recv(packet_size).decode()
                        if not chunk:
                            break
                        buffer += chunk
                        try:
                            received = json.loads(buffer)
                            buffer = ""  # ✅ clear after full JSON parse
                            break
                        except json.JSONDecodeError:
                            continue  # ✅ incomplete JSON, read next chunk
                    assert received["type"] == "ack"

                    print(f"Got ACK sacks: {received['sacks']}, id: {received['id']}")
                    if random.random() < simloss:
                        print("Dropped ack!")
                        continue

                    inflight -= sender.ack_packet(received["sacks"], received["id"])
                    assert inflight >= 0
                except socket.timeout:
                    inflight = 0
                    print("Timeout")
                    sender.timeout()


def main():
    parser = argparse.ArgumentParser(description="Transport assignment")
    parser.add_argument("role", choices=["sender", "receiver"], help="Role to play: 'sender' or 'receiver'")
    parser.add_argument("--ip", type=str, required=True, help="IP address to bind/connect to")
    parser.add_argument("--port", type=int, required=True, help="Port number to bind/connect to")
    parser.add_argument("--sendfile", type=str, required=False,
                        help="If role=sender, the file that contains data to send")
    parser.add_argument("--recv_window", type=int, default=15000, help="Receive window size in bytes")
    parser.add_argument("--simloss", type=float, default=0.0,
                        help="Simulate packet loss. Provide the fraction of packets (0-1) that should be randomly dropped")
    parser.add_argument("--pkts_to_reorder", type=int, default=1, help="Number of packets to shuffle randomly")

    args = parser.parse_args()

    if args.role == "receiver":
        start_receiver(args.ip, args.port)
    else:
        if args.sendfile is None:
            print("No file to send")
            return

        with open(args.sendfile, 'r') as f:
            data = f.read()
            start_sender(args.ip, args.port, data, args.recv_window, args.simloss, args.pkts_to_reorder)


if __name__ == "__main__":
    main()

