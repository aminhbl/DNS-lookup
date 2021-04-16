import binascii
import socket
import random


def lookup(domain_name, server_address):
    message = build_message(address=domain_name)
    returned_data = send_udp_message(message, server_address, 53)
    return binascii.hexlify(returned_data).decode()


def main(parts):
    print('Look for {} at {}'.format(parts[1], parts[0]))
    response = lookup(parts[1], parts[0])
    res, follow, answer_count, found_ip = parse_response(response)
    if len(res) == 0:
        print("didn't find it!")
        return

    print("\nResponse:", res)
    print("----------------------------------")
    print(follow)

    if answer_count > 0:
        print('Resolved IP for {} is {}'.format(parts[1], found_ip))
        return
    else:
        random.shuffle(follow)
        for ip in follow:
            new_parts = [ip, parts[1]]
            main(new_parts)


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

    QR = 0  # Query: 0, Response: 1     1bit
    OPCODE = 0  # Standard query            4bit
    AA = 0  # ?                         1bit
    TC = 0  # Message is truncated?     1bit
    RD = 0  # Recursion?                1bit
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

    if type == 28:
        return "AAAA"

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

    # Question section
    question_parts = parse_domain_name(response, 24, [])

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

    RR_start = QCLASS_STARTS + 4
    # Answer
    final_ip = ''
    if ANCOUNT > 0:
        decoded_response.append("\n# ANSWER SECTION")
        for AN in range(ANCOUNT):
            RR_start, temp_res, final_ip = parse_RR(RR_start, response, 'ANSWER', AN)
            if len(temp_res) == 0:
                return [], None, 0, None
            decoded_response.extend(temp_res)

    # Authority
    if NSCOUNT > 0:
        decoded_response.append("\n# AUTHORITY SECTION")
        for AN in range(NSCOUNT):
            RR_start, temp_res, _ = parse_RR(RR_start, response, "AUTHORITY", AN)
            if len(temp_res) == 0:
                return [], None, 0, None
            decoded_response.extend(temp_res)

    # Additional
    follow = []
    if ARCOUNT > 0:
        decoded_response.append("\n# ADDITIONAL SECTION")
        for AR in range(ARCOUNT):
            RR_start, temp_res, follow_up = parse_RR(RR_start, response, "ADDITIONAL", AR)
            if len(temp_res) == 0:
                return [], None, 0, None
            if follow_up is not None:
                follow.append(follow_up)
            decoded_response.extend(temp_res)

    return "\n".join(decoded_response), follow, ANCOUNT, final_ip


def parse_domain_name(message, start, parts):
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


def parse_RR(RR_start, response, RR_type, RR_number):
    decoded_RR = []
    resolved_ip = None
    if RR_start < len(response):
        ANAME = response[RR_start:RR_start + 4]
        ATYPE = response[RR_start + 4:RR_start + 8]
        try:
            get_type(int(ATYPE, 16))
        except:
            return None, [], None
        ACLASS = response[RR_start + 8:RR_start + 12]
        TTL = int(response[RR_start + 12:RR_start + 20], 16)
        RDLENGTH = int(response[RR_start + 20:RR_start + 24], 16)
        RDDATA = response[RR_start + 24:RR_start + 24 + (RDLENGTH * 2)]

        if ATYPE == get_type("A"):
            ip_parts = []
            for i in range(0, len(RDDATA), 2):
                ip_parts.append(RDDATA[i:i + 2])

            RDDATA_decoded = ''
            for part in ip_parts:
                RDDATA_decoded += str(int(part, 16)) + '.'
            RDDATA_decoded = RDDATA_decoded[:-1]
            resolved_ip = RDDATA_decoded
        elif ATYPE == "001c":
            ip_parts = []
            for i in range(0, len(RDDATA), 4):
                ip_parts.append(RDDATA[i:i + 4])

            RDDATA_decoded = ''
            for part in ip_parts:
                RDDATA_decoded += "{:x}".format(int(part, 16)) + ':'
            RDDATA_decoded = RDDATA_decoded[:-1]
        else:
            RDDATA_decoded = ".".join(map(lambda p: binascii.unhexlify(p).decode(), parse_domain_name(RDDATA, 0, [])))

        RR_start = RR_start + 24 + (RDLENGTH * 2)

    try:
        ATYPE
    except NameError:
        None
    else:
        decoded_RR.append("# " + RR_type + str(RR_number + 1))
        decoded_RR.append("ANAME: " + ANAME)
        decoded_RR.append("ATYPE: " + ATYPE + " (\"" + get_type(int(ATYPE, 16)) + "\")")
        decoded_RR.append("ACLASS: " + ACLASS)
        decoded_RR.append("\nTTL: " + str(TTL))
        decoded_RR.append("RDLENGTH: " + str(RDLENGTH))
        decoded_RR.append("RDDATA: " + RDDATA)
        decoded_RR.append("RDDATA decoded: " + RDDATA_decoded + "\n")

    return RR_start, decoded_RR, resolved_ip


if __name__ == '__main__':
    inputs = input("Enter the name address:\n")
    inputs = inputs.split()
    main(inputs)

    # print("{:04x}".format(123))
    # print(format(123, '04x'))
