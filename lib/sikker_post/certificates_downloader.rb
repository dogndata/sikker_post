
class CertificatesDownloader
  class << self
  	def ldap_connection
  		ldap = Net::LDAP.new  host: "crtdir.certifikat.dk", # your LDAP host name or IP goes here,
                      		  port: "389", # your LDAP host port goes here,
                      		  base: "c=dk" # the base of your AD tree goes here,
		ldap

  	end
# GET THE DISPLAY NAME AND E-MAIL ADDRESS FOR A SINGLE USER
#search_param = "philip.bergen@gmail.com"
#search_param = "max@synthmax.dk"
search_param = "max@ilab.dk"
result_attrs = ["cn", "usercertificate", "mail"]

# Build filter
search_filter = Net::LDAP::Filter.eq("mail", search_param)

# Execute search
ldap.search(:filter => search_filter, :attributes => result_attrs, :return_result => false) { |item| 
	puts "#{item.cn.first}:   (#{item.mail.first})" 


	#File.open("max.der", 'wb') { |f| f.write(str) }
}



#openssl x509 -in max.der -inform der -outform pem -out max.pem
 

	end
  end
end
