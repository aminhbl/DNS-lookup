import iterative_query
import recursive_query
import pickle


def write_to_file(res_dict):
    try:
        file = open('resolved', 'wb')
        pickle.dump(res_dict, file)
        file.close()
        print("Cache file has been updated!")
    except:
        print("Something went wrong")


def main():
    resolved = dict()
    try:
        with open('resolved', 'rb') as handle:
            data = handle.read()
        resolved = pickle.loads(data)
    except FileNotFoundError:
        print("Create new cache file!")

    while True:
        inputs = input("Enter the name address:\n")
        inputs = inputs.split()

        if len(inputs) == 1:
            if inputs[0] == "stop":
                exit()
            query(resolved, inputs[0], recursive_query.main, inputs[0])
            print("Cache:", resolved)
            print('\n\n')
        elif len(inputs) == 2:
            query(resolved, inputs[1], iterative_query.caching_main, inputs)
            print("Cache:", resolved)
            print('\n\n')
        else:
            print("Wrong input")


def query(resolved_dict, domain_name, send_query, inputs):
    try:
        if resolved_dict[domain_name][0] > 2:
            print("Resolved IP for {} is {}".format(domain_name, resolved_dict[domain_name][1]))
        else:
            raise Exception
    except:
        res_ip = send_query(inputs)
        try:
            resolved_dict[domain_name] = [resolved_dict[domain_name][0] + 1, resolved_dict[domain_name][1]]
        except:
            resolved_dict[domain_name] = [1, res_ip]

        if resolved_dict[domain_name][0] > 2:
            write_to_file(resolved_dict)


if __name__ == '__main__':
    main()
