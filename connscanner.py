import platform
import subprocess 
import shlex
import csv
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

print(new_array := delimiter_semicolon(preprocess_ouput()))  # -> print the output for the array of lines

