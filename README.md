## README：

+ #### Run in Linux:
    '''
    python rawsocket.py server_name
    '''

+ #### Description:

This is a Python implementation of a TCP client that uses raw sockets to send and receive data. It defines a custom `MyTCPSocket` class that allows the user to establish a TCP connection with a remote host, send data to the remote host, and receive data from the remote host.

The `MyTCPSocket` class has several instance variables that hold information about the state of the connection, such as the `local_host` and `local_port` of the client, the `remote_host` and `remote_port` of the server, the `send_buf` and `recv_buf` that hold the data to send and receive, and the `tcp_seq` and `tcp_ack_seq` that keep track of the sequence and acknowledgement numbers.

The class also defines several helper methods for packing and unpacking IP datagrams and TCP segments, as well as a `checksum` method that calculates the checksum for a given payload.

The `pack_ip_datagram` method generates an IP datagram by packing the IP header and the TCP segment payload. The `pack_tcp_segment` method generates a TCP segment by packing the TCP header and payload.

The implementation uses several constants to define the flags and format strings used in the IP and TCP headers. The `SYN`, `ACK`, `SYN_ACK`, `FIN`, `FIN_ACK`, and `PSH_ACK` constants define the different TCP flags, and the `IP_HDR_FMT`, `TCP_HDR_FMT`, and `PSH_FMT` constants define the format strings for the IP header, TCP header, and PSH header, respectively.

The implementation also defines a `checksum` method that calculates the checksum for a given payload. This method is used to calculate the checksum for the IP header and TCP header.

