import csv
import recursive_query


def main():
    ip_addresses = []
    with open('domain-names.csv') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        for row in csv_reader:
            ip_addresses.append(recursive_query.main(row[0]))

        write_to_csv(ip_addresses)


def write_to_csv(ips):
    with open('ip-addresses.csv', mode='w') as csv_file:
        writer = csv.writer(csv_file)
        for ip in ips:
            li = [ip]
            writer.writerow(li)


if __name__ == '__main__':
    main()
