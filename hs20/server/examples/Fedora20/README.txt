This documents part of my adventure in getting basic HS20-R2
configuration working on two Linux machines.
Thanks to lots of help from Jouni on the hostapd mailing list!

--Ben Greear <greearb@candelatech.com>

You may of course change these specifics to fit your own machine,
but it is hoped that a very specific example will be helpful for
anyone trying to set this up themselves.

Create a user 'lanforge' and CD into it's directory: cd /home/lanforge

un-tar hs20.tar.gz in this directory.

See the hs20/AS/ directory for 4 hostapd config files.  Two are
for hostapd-radius instances, two are for VAP instances.  You
will need to at least edit device names and bssid info at least.

Update /etc/hosts for the 'virtual' servers.  The
IP address must match your own machine of course.
The station machine will need to be able to resolve
the hosts as well.

# cat /etc/hosts
127.0.0.1	localhost.localdomain localhost
::1		localhost6.localdomain6 localhost6

192.168.100.85 osu-client.ben-ota-2.lanforge.local
192.168.100.85 osu-server.ben-ota-2.lanforge.local
192.168.100.85 osu-signup.ben-ota-2.lanforge.local
192.168.100.85       ocsp.ben-ota-2.lanforge.local


ocsp.bash starts the OCSP service, then start up your hostapd
instances as appropriate.

The built hs20_spp_server should be placed at:  hs20/spp/hs20_spp_server



On the station machine, create a directory called osu_wlan
and cd into it.  Place the built hs20-osu-client in ~lanforge/

Copy the ca.pem file from AP machine to the local machine:
scp osu-server.ben-ota-2.lanforge.local:/home/lanforge/hs20/ca/ca.pem ./osu-ca.pem

Copy the devdetail.xml, devinfo.xml, and spp.xsd files to the ./ directory as well.

Start the HS20-R2 client:

Remove any conflicting data from previous runs:
rm -f SP/ben-ota-2.lanforge.local/pps.xml

~lanforge/hs20-osu-client -x spp.xsd -dd -S wlan1 signup

You should get a web-client window with a LANforge icon and info, then click on
the free-access and accept links.


Verify that your station properly connected the non-OSEN AP after the
hs20-osu-client program completes.

For the adventurous, take a look at the lf_kinstall.txt file found at
http://www.candelatech.com/lf_kinstall.txt
It has (or will have, as soon as the latest code is deemed stable)
logic to automatically create all of the keys and so forth.  It is
designed for a specific goal, but the astute user could use it's
logic to better understand how to create their own HS20 setup.
