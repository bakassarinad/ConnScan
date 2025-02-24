import platform
import subprocess 
import shlex
import csv
import os
CSV_FILE = 'connections.csv'

def get_ip_threat_intelligence(ip):
    pass

def running_command_string():
    if platform.system() == 'Windows':
        # netstat -n Displays addresses and port numbers in numerical forms
        # netstat -a Displays all connections and listening ports
        # which are ESTABLISHED
        netstat_command = 'netstat -na | findstr ESTABLISHED'
    else:
        # for Linux
        netstat_command = 'netstat -na | grep ESTABLISHED'
    return netstat_command

def output_command():
     # running shell command (cli)
     output = subprocess.check_output(running_command_string().split(), shell=True)
     output = output.decode('utf-8') 
     return output

#Check for the output of above function
print(type(output_command()))

def preprocess_ouput():
    lines = output_command().split('\n')
    new_lines = []
    # print(len(lines))
    for line in lines:
        line = " ".join(line.split())   # remove extra spaces
        if line != '':
            line = line.split(' ')
            new_lines.append(line)

    return new_lines

# print(preprocess_ouput())  # -> print the output for the array of lines


def delimiter_semicolon(array):
    new_array = []
    for line in array:
        line[1] = line[1].split(':')
        ip, port = line[1][0], line[1][1]
        line[2] = line[2].split(':')
        ip2, port2 = line[2][0], line[2][1]
        new_array.append([line[0], ip, port, ip2, port2, line[3]])
    return new_array

#print(new_array := delimiter_semicolon(preprocess_ouput()))  # -> print the output for the array of lines

def write_to_new_csv(array):
    
    with open(CSV_FILE, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Protocol', 'Local Address', 'Local Port', 'Destination Address', 'Destination Port', 'State'])
        writer.writerows(array)

def write_to_existed_csv(array):
    with open(CSV_FILE, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(array)

def read_past_connections():
    past_connections = []
    if os.path.exists(CSV_FILE):
        with open(CSV_FILE, 'r') as file:
            reader = csv.reader(file)
            for line in reader:
                past_connections.append(line)
    return past_connections

active_connections = delimiter_semicolon(preprocess_ouput())
print(active_connections)
print(len(active_connections))
past_connections = read_past_connections()
print(len(past_connections))
print(len([conn for conn in active_connections if conn not in past_connections]))
write_to_existed_csv([conn for conn in active_connections if conn not in past_connections])

all_connections = read_past_connections()

print('\n'.join(['\t'.join([str(cell) for cell in row]) for row in all_connections]))