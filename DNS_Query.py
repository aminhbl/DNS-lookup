import binascii
import socket


def main():
    domain_name = input("Enter the name address:\n")
    message = build_message(address=domain_name)
    response = send_udp_message(message, "1.1.1.1", 53)
    print("\nResponse:\n" + response)
    print("\nResponse (decoded):" + parse_response(response))


def send_udp_message(message, address, port):
    message = message.replace(" ", "").replace("\n", "")
    server_address = (address, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(binascii.unhexlify(message), server_address)
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return binascii.hexlify(data).decode()


def build_message(type="A", address=""):
    message = ""

    QR = 0  # Query: 0, Response: 1     1bit
    OPCODE = 0  # Standard query            4bit
    AA = 0  # ?                         1bit
    TC = 0  # Message is truncated?     1bit
    RD = 1  # Recursion?                1bit
    RA = 0  # ?                         1bit
    Z = 0  # ?                         3bit
    RCODE = 0  # ?                         4bit

    flags = str(QR)
    flags += str(OPCODE).zfill(4)
    flags += str(AA) + str(TC) + str(RD) + str(RA)
    flags += str(Z).zfill(3)
    flags += str(RCODE).zfill(4)
    flags = "{:04x}".format(int(flags, 2))

    QDCOUNT = 1  # Number of questions           4bit
    ANCOUNT = 0  # Number of answers             4bit
    NSCOUNT = 0  # Number of authority records   4bit
    ARCOUNT = 0  # Number of additional records  4bit

    ID = 43690  # 16-bit identifier (0-65535) # 43690 equals 'aaaa'
    message += "{:04x}".format(ID)
    message += flags
    message += "{:04x}".format(QDCOUNT)
    message += "{:04x}".format(ANCOUNT)
    message += "{:04x}".format(NSCOUNT)
    message += "{:04x}".format(ARCOUNT)

    # QNAME is url split up by '.', preceded by int indicating length of part
    address_parts = address.split(".")
    for part in address_parts:
        addr_len = "{:02x}".format(len(part))
        addr_part = part.encode().hex()
        message += addr_len
        message += addr_part

    message += "00"  # Terminating bit for QNAME

    # Type of request
    QTYPE = get_type(type)
    message += QTYPE

    # Class for lookup. 1 is Internet
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

    QDCOUNT = response[8:12]
    ANCOUNT = response[12:16]
    NSCOUNT = response[16:20]
    ARCOUNT = response[20:24]

    # Question section
    question_parts = parse_parts(response, 24, [])

    # print('question parts', bytearray.fromhex(question_parts[0]).decode())

    QNAME = ""
    QTYPE_STARTS = 0
    for part in question_parts:
        QNAME += binascii.unhexlify(part).decode() + "."
        QTYPE_STARTS += len(part)
    QNAME = QNAME[:-1]

    QTYPE_STARTS += 24 + (len(question_parts) * 2) + 2
    QCLASS_STARTS = QTYPE_STARTS + 4

    QTYPE = response[QTYPE_STARTS:QCLASS_STARTS]
    QCLASS = response[QCLASS_STARTS:QCLASS_STARTS + 4]

    decoded_response.append("\n# QUESTION SECTION")
    decoded_response.append("QNAME: " + QNAME)
    decoded_response.append("QTYPE: " + QTYPE + " (\"" + get_type(int(QTYPE, 16)) + "\")")
    decoded_response.append("QCLASS: " + QCLASS)

    # Answer section
    ANSWER_SECTION_STARTS = QCLASS_STARTS + 4

    NUM_ANSWERS = max([int(ANCOUNT, 16), int(NSCOUNT, 16), int(ARCOUNT, 16)])
    if NUM_ANSWERS > 0:
        decoded_response.append("\n# ANSWER SECTION")

        for ANSWER_COUNT in range(NUM_ANSWERS):
            if ANSWER_SECTION_STARTS < len(response):
                ANAME = response[ANSWER_SECTION_STARTS:ANSWER_SECTION_STARTS + 4]  # Refers to Question
                ATYPE = response[ANSWER_SECTION_STARTS + 4:ANSWER_SECTION_STARTS + 8]
                ACLASS = response[ANSWER_SECTION_STARTS + 8:ANSWER_SECTION_STARTS + 12]
                TTL = int(response[ANSWER_SECTION_STARTS + 12:ANSWER_SECTION_STARTS + 20], 16)
                RDLENGTH = int(response[ANSWER_SECTION_STARTS + 20:ANSWER_SECTION_STARTS + 24], 16)
                RDDATA = response[ANSWER_SECTION_STARTS + 24:ANSWER_SECTION_STARTS + 24 + (RDLENGTH * 2)]

                if ATYPE == get_type("A"):
                    # octets = [RDDATA[i:i + 2] for i in range(0, len(RDDATA), 2)]
                    # print('octets')
                    # print(octets)
                    ip_parts = []
                    for i in range(0, len(RDDATA), 2):
                        ip_parts.append(RDDATA[i:i + 2])

                    RDDATA_decoded = ''
                    for part in ip_parts:
                        RDDATA_decoded += str(int(part, 16)) + '.'
                    RDDATA_decoded = RDDATA_decoded[:-1]
                    # RDDATA_decoded = ".".join(list(map(lambda x: str(int(x, 16)), ip_parts)))
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
                decoded_response.append("QDCOUNT: " + str(int(QDCOUNT, 16)))
                decoded_response.append("ANCOUNT: " + str(int(ANCOUNT, 16)))
                decoded_response.append("NSCOUNT: " + str(int(NSCOUNT, 16)))
                decoded_response.append("ARCOUNT: " + str(int(ARCOUNT, 16)))

                decoded_response.append("ANAME: " + ANAME)
                decoded_response.append("ATYPE: " + ATYPE + " (\"" + get_type(int(ATYPE, 16)) + "\")")
                decoded_response.append("ACLASS: " + ACLASS)

                decoded_response.append("\nTTL: " + str(TTL))
                decoded_response.append("RDLENGTH: " + str(RDLENGTH))
                decoded_response.append("RDDATA: " + RDDATA)
                decoded_response.append("RDDATA decoded (result): " + RDDATA_decoded + "\n")
    print('rest of the response')
    print(response[ANSWER_SECTION_STARTS:])

    # Authority


    return "\n".join(decoded_response)


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

    # if len(part_len) == 0:
    #     return parts
    #
    # part_end = part_start + (int(part_len, 16) * 2)
    # parts.append(message[part_start:part_end])
    #
    # if message[part_end:part_end + 2] == "00" or part_end > len(message):
    #     return parts
    # else:
    #     return parse_parts(message, part_end, parts)


if __name__ == '__main__':
    main()

    # print("{:04x}".format(123))
    # print(format(123, '04x'))
