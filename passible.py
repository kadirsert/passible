#!/usr/bin/env python

from passlib.hash import sha512_crypt
import string
import random
import os
import sys
import re
import pexpect
import argparse
import getpass

__location__ = os.path.dirname(os.path.abspath(__file__))


def generate_password():
    str_lower = ''.join(random.choice(string.ascii_lowercase) for _ in range(7))
    str_upper = ''.join(random.choice(string.ascii_uppercase) for _ in range(2))
    str_digit = ''.join(random.choice(string.digits) for _ in range(2))
    str_special = ''.join(random.choice('+*-') for _ in range(1))
    strc = str_lower + str_upper + str_digit + str_special
    return ''.join(random.sample(strc,len(strc)))

def execute_ansible_cmd(ansible_cmd):
    child = pexpect.spawn(ansible_cmd)
    child.setecho(False)
    if args.vaultpwd:
        child.expect ("Vault password:")
        child.sendline(vault_pass)
    child.expect(pexpect.EOF)
    expect_out = child.before.strip()
    child.close()
    return expect_out


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--inventory", help="For Ansible inventory file location.", dest="inventory")
    parser.add_argument("-vp", "--vaultpwd", help="Ask for Ansible Vault password.", action="store_true", dest="vaultpwd")
    parser.add_argument("-gn", "--groupname", help="Ansible Group Name", dest="groupname")
    args = parser.parse_args()
    inv_file_location = ' '
    ask_vault_pass = ' '
    if args.inventory:
        inv_file_location = ' -i ' + args.inventory + ' '
    if args.vaultpwd:
        ask_vault_pass = ' --ask-vault-pass '
        vault_pass = getpass.getpass('Enter Vault Pass: ')
    if args.groupname:
        host_group_name = args.groupname
        server_list = []
        cmd = "/usr/bin/ansible" + inv_file_location + host_group_name + ask_vault_pass + "--list-hosts"
        proc_out = execute_ansible_cmd(cmd)
        for line in proc_out.split('\n'):
            server_list.append(line.strip())
        del server_list[0]

        try:
            pw_file = open(os.path.join(__location__, 'passible_' + host_group_name), 'w')
            passible_out = ''
            for server in server_list:
                server_short = server.split('.')[0]
                passwd = generate_password()
                cmd = "/usr/bin/ansible" + inv_file_location + server + ask_vault_pass + "-m setup -a 'filter=ansible_default_ipv4'"
                proc_out = execute_ansible_cmd(cmd)
                regex = re.compile(r'(.*\|\s(CHANGED|SUCCESS))\s=>.+ansible_default_ipv4.+\"address\":\s\"(\d+\.\d+\.\d+\.\d+)\",.+\"type\":\s\"(ether|bonding|bridge)\"', re.IGNORECASE | re.DOTALL)
                match = regex.match(proc_out)
                if match:
                    server_ip_addr = regex.search(proc_out).group(2).strip()
                cmd = "/usr/bin/ansible" + inv_file_location + server + ask_vault_pass + "-m user -a 'name=root password=" + sha512_crypt.encrypt(passwd) + "'"
                proc_out = execute_ansible_cmd(cmd)
                print proc_out
                regex = re.compile(r'(.*\|\s(CHANGED|SUCCESS))\s=>.+\"changed\":\strue,', re.IGNORECASE | re.DOTALL)
                match = regex.match(proc_out)
                if match:
                    passible_out = passible_out + host_group_name + ' ' + server + ' ' + server_ip_addr + ' ' + passwd + '\n'
            pw_file.write(passible_out)
        finally:
            pw_file.close()
    else:
        print "An Ansible host group should be specified as a parameter! A group name you may choose:"
        cmd = "/usr/bin/ansible" + inv_file_location + "localhost" + ask_vault_pass  + "-m debug -a 'var=groups.keys()'"
        proc_out = execute_ansible_cmd(cmd)
        regex = re.compile(r'.*\"groups.keys\(\)\":\s\[(.*)\]', re.DOTALL)
        group_list = regex.search(proc_out).group(1)
        for line in group_list.split('\n'):
            print line.strip().replace("\"", "").replace(",", "")

