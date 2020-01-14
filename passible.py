#!/usr/bin/env python
# -*- coding: utf-8 -*-

from passlib.hash import sha512_crypt
from os.path import expanduser
import string
import random
import os
import re
import pexpect
import argparse
import getpass
import gnupg

__location__ = os.path.dirname(os.path.abspath(__file__))


def generate_password():
    str_lower = ''.join(random.choice(string.ascii_lowercase) for _ in range(7))
    str_upper = ''.join(random.choice(string.ascii_uppercase) for _ in range(2))
    str_digit = ''.join(random.choice(string.digits) for _ in range(2))
    str_special = ''.join(random.choice('+*-') for _ in range(1))
    strc = str_lower + str_upper + str_digit + str_special
    return ''.join(random.sample(strc, len(strc)))


def execute_ansible_cmd(ansible_cmd):
    child = pexpect.spawn(ansible_cmd)
    child.setecho(False)
    if args.vaultpwd:
        child.expect("Vault password:")
        child.sendline(vault_pass)
    child.expect(pexpect.EOF)
    expect_out = child.before.strip()
    child.close()
    return expect_out


if __name__ == '__main__':
    gpg = gnupg.GPG()
    gpg.encoding = 'utf-8'
    output_directory = expanduser("~")
    parser = argparse.ArgumentParser()
    parser.add_argument("-gn", "--groupname", help="Hostgroup name.")
    parser.add_argument("-i", "--inventory", help="Custom inventory file.")
    parser.add_argument("-ru", "--remoteuser", help="Remote username whose password will be changed.", default="root")
    parser.add_argument("-vp", "--vaultpwd", help="Enable asking for vault password.", action="store_true")
    parser.add_argument("-b", "--become", help="Enable privilege escalation.", action="store_true")
    parser.add_argument("-o", "--outputdir", help="Directory for the GPG encrypted password output.",
                        default=output_directory)
    parser.add_argument("-tg", "--testgpg", help="Test GPG output.", action="store_true")
    args = parser.parse_args()
    inv_file_location = ' '
    ask_vault_pass = ' '
    become = ' '
    if args.testgpg:
        test_str = raw_input("Enter an example string: ")
        gpg_test_pass = getpass.getpass('Enter a GPG Passphrase to test if encryption is working: ')
        try:
            encrypted = str(gpg.encrypt(test_str + '\n', recipients=None, symmetric=True, passphrase=gpg_test_pass))
            with open(os.path.join(args.outputdir, 'passible_test.gpg'), 'w') as test_file:
                test_file.write(encrypted)
            print "Output is written to " + test_file.name + " , you can decrypt it using command: gpg -d " + test_file.name
        except Exception as error:
            print(error)
    else:
        if args.inventory:
            inv_file_location = ' -i ' + args.inventory + ' '
        if args.vaultpwd:
            ask_vault_pass = ' --ask-vault-pass '
            vault_pass = getpass.getpass('Enter Vault Pass: ')
        if args.become:
            become = ' --become '
        if args.groupname:
            host_group_name = args.groupname
            gpg_pass = getpass.getpass('Enter a GPG Passphrase to encrypt passible\'s output: ')
            server_list = []
            cmd = "/usr/bin/ansible" + inv_file_location + host_group_name + ask_vault_pass + "--list-hosts"
            proc_out = execute_ansible_cmd(cmd)
            for line in proc_out.split('\n'):
                server_list.append(line.strip())
            del server_list[0]

            try:
                server_ip_addr = ''
                passible_out = ''
                for server in server_list:
                    server_short = server.split('.')[0]
                    passwd = generate_password()
                    cmd = "/usr/bin/ansible" + inv_file_location + server + become + ask_vault_pass + "-m setup -a 'filter=ansible_default_ipv4'"
                    proc_out = execute_ansible_cmd(cmd)
                    regex = re.compile(
                        r'(.*\|\s(CHANGED|SUCCESS))\s=>.+ansible_default_ipv4.+\"address\":\s\"(\d+\.\d+\.\d+\.\d+)\",.+\"type\":\s\"(ether|bonding|bridge)\"',
                        re.IGNORECASE | re.DOTALL)
                    match = regex.match(proc_out)
                    if match:
                        server_ip_addr = regex.search(proc_out).group(3).strip()
                    cmd = "/usr/bin/ansible" + inv_file_location + server + become + ask_vault_pass + "-m user -a 'name=" + args.remoteuser + " password=" + sha512_crypt.encrypt(
                        passwd) + "'"
                    proc_out = execute_ansible_cmd(cmd)
                    print proc_out
                    regex = re.compile(r'(.*\|\s(CHANGED|SUCCESS))\s=>.+\"changed\":\strue,', re.IGNORECASE | re.DOTALL)
                    match = regex.match(proc_out)
                    if match:
                        passible_out = passible_out + host_group_name + ' ' + server + ' ' + server_ip_addr + ' ' + args.remoteuser + ' ' + passwd + '\n'
                encrypted = str(gpg.encrypt(passible_out, recipients=None, symmetric=True, passphrase=gpg_pass))
                with open(os.path.join(args.outputdir, 'passible_' + host_group_name + '.gpg'), 'w') as pw_file:
                    pw_file.write(encrypted)
                print "Output is written to " + pw_file.name + " , you can decrypt it using command: gpg -d " + pw_file.name
            except Exception as error:
                print(error)
        else:
            print "An Ansible host group should be specified as a parameter! A group name you may choose:"
            cmd = "/usr/bin/ansible" + inv_file_location + "localhost" + ask_vault_pass + "-m debug -a 'var=groups.keys()'"
            proc_out = execute_ansible_cmd(cmd)
            regex = re.compile(r'.*\"groups.keys\(\)\":\s\[(.*)\]', re.DOTALL)
            group_list = regex.search(proc_out).group(1)
            for line in group_list.split('\n'):
                print line.strip().replace("\"", "").replace(",", "")
            parser.print_help()
