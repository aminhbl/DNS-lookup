import binascii
import pickle
import socket
import cache_query


def main(domain_name):
    query = build_message(address=domain_name)
    returned_data = send_udp_message(query, "1.1.1.1", 53)
    response = binascii.hexlify(returned_data).decode()
    res, res_ip = parse_response(response)
    print("\nResponse:\n" + res)
    print("----------")
    print("Resolved IP for {} is {}".format(domain_name, res_ip))
    return res_ip


def send_udp_message(message, address, port):
    message = message.replace(" ", "").replace("\n", "")
    server_address = (address, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(binascii.unhexlify(message), server_address)
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return data


def build_message(type="A", address=""):
    message = ""

    QR = 0
    OPCODE = 0
    AA = 0
    TC = 0
    RD = 1
    RA = 0
    Z = 0
    RCODE = 0

    flags = str(QR)
    flags += str(OPCODE).zfill(4)
    flags += str(AA) + str(TC) + str(RD) + str(RA)
    flags += str(Z).zfill(3)
    flags += str(RCODE).zfill(4)
    flags = "{:04x}".format(int(flags, 2))

    QDCOUNT = 1
    ANCOUNT = 0
    NSCOUNT = 0
    ARCOUNT = 0

    ID = 43690
    message += "{:04x}".format(ID)
    message += flags
    message += "{:04x}".format(QDCOUNT)
    message += "{:04x}".format(ANCOUNT)
    message += "{:04x}".format(NSCOUNT)
    message += "{:04x}".format(ARCOUNT)

    address_parts = address.split(".")
    for part in address_parts:
        addr_len = "{:02x}".format(len(part))
        addr_part = part.encode().hex()
        message += addr_len
        message += addr_part
    message += "00"

    QTYPE = get_type(type)
    message += QTYPE

    QCLASS = 1
    message += "{:04x}".format(QCLASS)

    return message


def get_type(type):
    types = [
        "ERROR",
        "A",
        "NS",
        "MD",
        "MF",
        "CNAME",
        "SOA",
        "MB",
        "MG",
        "MR",
        "NULL",
        "WKS",
        "PTS",
        "HINFO",
        "MINFO",
        "MX",
        "TXT"
    ]

    return "{:04x}".format(types.index(type)) if isinstance(type, str) else types[type]


def parse_response(response):
    decoded_response = []

    ID = response[0:4]
    decoded_response.append("\nHEADER: ")
    decoded_response.append("ID: " + ID)
    decoded_response.append("Query Flags: ")

    flags = response[4:8]
    flags = "{:b}".format(int(flags, 16)).zfill(16)

    QR = flags[0:1]
    decoded_response.append("QR: " + QR)
    OPCODE = flags[1:5]
    decoded_response.append("OPCODE: " + OPCODE)
    AA = flags[5:6]
    decoded_response.append("AA: " + AA)
    TC = flags[6:7]
    decoded_response.append("TC: " + TC)
    RD = flags[7:8]
    decoded_response.append("RD: " + RD)
    RA = flags[8:9]
    decoded_response.append("RA: " + RA)
    Z = flags[9:12]
    decoded_response.append("Z: " + Z)
    RCODE = flags[12:16]
    decoded_response.append("RCODE: " + RCODE)

    QDCOUNT = int(response[8:12], 16)
    ANCOUNT = int(response[12:16], 16)
    NSCOUNT = int(response[16:20], 16)
    ARCOUNT = int(response[20:24], 16)

    decoded_response.append("QDCOUNT: " + str(QDCOUNT))
    decoded_response.append("ANCOUNT: " + str(ANCOUNT))
    decoded_response.append("NSCOUNT: " + str(NSCOUNT))
    decoded_response.append("ARCOUNT: " + str(ARCOUNT))

    # Question
    question_parts = parse_parts(response, 24, [])

    QNAME = ""
    QTYPE_STARTS = 0
    for part in question_parts:
        QNAME += bytearray.fromhex(part).decode() + "."
        QTYPE_STARTS += len(part)
    QNAME = QNAME[:-1]

    QTYPE_STARTS += 24 + (len(question_parts) * 2) + 2
    QCLASS_STARTS = QTYPE_STARTS + 4

    QTYPE = response[QTYPE_STARTS:QCLASS_STARTS]
    QCLASS = response[QCLASS_STARTS:QCLASS_STARTS + 4]

    decoded_response.append("\nQUESTION:")
    decoded_response.append("QNAME: " + QNAME)
    decoded_response.append("QTYPE: " + QTYPE + " (\"" + get_type(int(QTYPE, 16)) + "\")")
    decoded_response.append("QCLASS: " + QCLASS)

    # Answer
    resolved_ip = ''
    ANSWER_SECTION_STARTS = QCLASS_STARTS + 4

    if ANCOUNT > 0:
        decoded_response.append("\nANSWER:")

        for ANSWER_COUNT in range(ANCOUNT):
            if ANSWER_SECTION_STARTS < len(response):
                ANAME = response[ANSWER_SECTION_STARTS:ANSWER_SECTION_STARTS + 4]  # Refers to Question
                ATYPE = response[ANSWER_SECTION_STARTS + 4:ANSWER_SECTION_STARTS + 8]
                ACLASS = response[ANSWER_SECTION_STARTS + 8:ANSWER_SECTION_STARTS + 12]
                TTL = int(response[ANSWER_SECTION_STARTS + 12:ANSWER_SECTION_STARTS + 20], 16)
                RDLENGTH = int(response[ANSWER_SECTION_STARTS + 20:ANSWER_SECTION_STARTS + 24], 16)
                RDDATA = response[ANSWER_SECTION_STARTS + 24:ANSWER_SECTION_STARTS + 24 + (RDLENGTH * 2)]

                if ATYPE == get_type("A"):
                    ip_parts = []
                    for i in range(0, len(RDDATA), 2):
                        ip_parts.append(RDDATA[i:i + 2])

                    RDDATA_decoded = ''
                    for part in ip_parts:
                        RDDATA_decoded += str(int(part, 16)) + '.'
                    RDDATA_decoded = RDDATA_decoded[:-1]
                    resolved_ip = RDDATA_decoded
                else:
                    RDDATA_decoded = ".".join(
                        map(lambda p: binascii.unhexlify(p).decode('iso8859-1'), parse_parts(RDDATA, 0, [])))

                ANSWER_SECTION_STARTS = ANSWER_SECTION_STARTS + 24 + (RDLENGTH * 2)

            try:
                ATYPE
            except NameError:
                None
            else:
                decoded_response.append("# ANSWER " + str(ANSWER_COUNT + 1))
                decoded_response.append("ANAME: " + ANAME)
                decoded_response.append("ATYPE: " + ATYPE + " (\"" + get_type(int(ATYPE, 16)) + "\")")
                decoded_response.append("ACLASS: " + ACLASS)

                decoded_response.append("\nTTL: " + str(TTL))
                decoded_response.append("RDLENGTH: " + str(RDLENGTH))
                decoded_response.append("RDDATA: " + RDDATA)
                decoded_response.append("RDDATA decoded: " + RDDATA_decoded + "\n")

    return "\n".join(decoded_response), resolved_ip


def parse_parts(message, start, parts):
    part_start = start + 2
    part_len = message[start:part_start]

    while len(part_len) != 0:
        end = part_start + (int(part_len, 16) * 2)
        parts.append(message[part_start:end])
        if message[end:end + 2] == "00" or end > len(message):
            return parts
        part_start = end + 2
        part_len = message[end:part_start]
    return parts


if __name__ == '__main__':
    address = input("Enter name address:\n")
    main(address)
