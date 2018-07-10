# tcp socketeer
# find tcp socket matches across multiple packet capture files

# ability to run external tools
from subprocess import getoutput, check_output, CalledProcessError
# for regex
import re
# for filesystem
import os
import glob


def print_header():
    print('#'*50)
    print('TCP Socketeer')
    print('#' * 50)


def print_some_helptext():
    print('#' * 50)
    print('H E L P  T E X T')


def get_windump_location():
    windump_location = ""
    while not windump_location:
        windump_location = input('Please specify the full filename path to the location of WinDump.exe: ')

        try:
            windump_output = getoutput(windump_location + " -V")
            windump_version_re = re.compile('version [0-9]\.[0-9]\.[0-9], based on tcpdump version [0-9]\.[0-9]\.[0-9]')
            windump_match = windump_version_re.search(windump_output)
            if windump_match:
                print('WinDump.exe {} was found at location {}.'.format(windump_match.group(), windump_location))

        except CalledProcessError as CPE:
            if CPE.returncode == 1:
                # normal for the help output of WinDump.exe
                # continue
                return windump_location
            else:
                print("Error: {}".format(CPE.output))
        except FileNotFoundError as FNF:
            print("File not found error: {}".format(FNF.strerror))


def get_file_list():
    cap_file_location = ""
    file_list = ""
    while not file_list:
        while not cap_file_location:
            cap_file_location = input('Please specify the full folder path to the location of the capture files: ')
            if os.path.isdir(cap_file_location):
                break
        # use glob to glob stuff together
        # i just like writing the word glob
        file_list = glob.glob(cap_file_location + '*.pcap')
        file_list.extend(glob.glob((cap_file_location + '*.pcapng')))
        # return a list of filenames for analysis
        if file_list:
            return file_list
        else:
            print('No pcap or pcapng files found at location {} - please try again'.format(cap_file_location))
            break


def get_all_packet_data(windump_location, cap_files_list):
    windump_packet_output = ""
    tcpdump_arguments = input('Please specify optional WinDump (tcpdump) arguments to narrow down packet processing: ')
    for each capfile in cap_files_list:
        windump_packet_output = windump_location + getoutput(windump_location + '-S -n -r' + cap_file)

    return windump_packet_output


def main():
    print_header()
    windump_location = get_windump_location()
    cap_files_list = get_file_list()
    packet_list = get_all_packet_data(windump_location, cap_files_list)



if __name__ == '__main__':
    main()