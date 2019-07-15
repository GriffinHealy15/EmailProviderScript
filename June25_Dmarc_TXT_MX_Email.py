import subprocess
import shlex
import datetime

#6-23-2019 -- 11:45:23 AM -- Griffin Healy 

# Python script gets dmarc, txt, spf, and email provider records on list of domains from input file; sends results to output file
# (1) takes a list of domains from an input file
# (2) collects the dmarc record, txt records, and spf record for each domain in the list
# (3) using a domains retrieved mx record, it finds the records organization or customer name if lack of organization
# (4) sends the domain, dmarc record to an output file
# (5) sends the domain, txt record to an output file
# (6) sends the domain, spf record to an output file
# (7) sends the domain, mx record to its own output file
# (8) sends the domain, email provider information to its own output file

# open input file, to read text
path_in = '/home/griffin/Python3.7_Projects/MX_EmailProvider_Script_June11_19/Input_File.txt'
# open output spf_dmarc_txt file, to write text
path_out = '/home/griffin/Python3.7_Projects/MX_EmailProvider_Script_June11_19/Output_SPF_DMARC_TXT.txt'
dmarc_output_txt = open(path_out,'a+') # opened text file
# open output mx file, to write text
path_out1 = '/home/griffin/Python3.7_Projects/MX_EmailProvider_Script_June11_19/Output_MX.txt' 
mx_output_txt = open(path_out1,'a+') # opened text file
# open output mx file, to write text
path_out2 = '/home/griffin/Python3.7_Projects/MX_EmailProvider_Script_June11_19/Output_EmailProvider.txt'
email_provider_output_txt = open(path_out2,'a+') # opened text file

# get current date in correct format
try:
    dt = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
except:
    dt = "DateNotFound"

global domain_processed
domain_processed = ""


with open(path_in, 'r') as dmarc_input_txt:

    # function runs opens subprocess to get dmarc
    def retrieve_dmarc(dmarc_subprocess):
        try:
            #run dig command on all lines in the text file , out is output of the collected dmarc or empty
            proc=subprocess.Popen(shlex.split(dmarc_subprocess),stdout=subprocess.PIPE)
            out,err=proc.communicate()

            # convert dmarc (in bytes) to a string
            byte_to_string_dmarc = str(out, 'utf-8')

            # check if dmarc exists, write it to output file
            if byte_to_string_dmarc != "":
                if ' ' in domain_remove_newline:
                    byte_to_string_dmarc_new = byte_to_string_dmarc.rstrip()
                    domain_plus_dmarc_ns = "".join((domain_remove_newline,",","DMARC,", byte_to_string_dmarc_new,",",dt, "\n"))
                    dmarc_output_txt.write(domain_plus_dmarc_ns)
                else:
                    byte_to_string_dmarc_new = byte_to_string_dmarc.rstrip()
                    domain_plus_dmarc = "".join((domain_remove_newline,",","DMARC,", byte_to_string_dmarc_new,",",dt, "\n"))
                    dmarc_output_txt.write(domain_plus_dmarc)
            else:
                #if ' ' in domain_remove_newline:
                domain_plus_no_record = "".join((domain_remove_newline, ",", "DMARC,","NoRecord,",dt,"\n"))
                dmarc_output_txt.write(domain_plus_no_record)
                #else:
                    #domain_plus_no_record = "".join((domain_remove_newline, ", ", "NO RECORD", "\n"))
                    #dmarc_output_txt.write(domain_plus_no_record)
        except:
            print("Error retrieving DMARC")
    # runs whois command, e.g. whois 192.222.222.222, returns info, parses out the highest cidr of each section and itscorresponding org/cust,
    # stores e.g. [cidr (section 1), cidr (section 2)], stores [organization (section 1), customer (section 2)]
    def whois_execute_parse(address, mx_subprocess, domain_to_pass_mx):
        try:
            global cidr_array
            cidr_array = []
            global organization_customer_name
            organization_customer_name = []
            global recursive_whois_counter
            # try to run whois on the passed in address, if any fail, we hit the except
            try:
                whois_command = ("whois ")
                whois_command_plus_address = "".join((whois_command, address))
                #print(whois_command_plus_address)
                proc=subprocess.Popen(shlex.split(whois_command_plus_address),stdout=subprocess.PIPE)
                out,err=proc.communicate()
                #convert whois (in bytes) to a string
                byte_to_string_whois = str(out, 'utf-8') # if no error, continue parsing out all the CIDRS in all sections
                if "No whois server is known for this kind of object." not in byte_to_string_whois and "Error" not in byte_to_string_whois:
                    cidr_count = byte_to_string_whois.count("CIDR:")
                    cidr_all = ["a%d" % x for x in range(cidr_count)]
                    try:
                        cidr_all = byte_to_string_whois.split("CIDR:")
                    except:
                        cidr_all = []
                    # for each cidr, basically break up into the sections of CIDR's and Organization/Customer names
                    for each_cidr in cidr_all:
                        current_greatest_final_cidr = 0
                        # break up into organizations or customers
                        if cidr_all.index(each_cidr) != 0:
                            try:
                                cidr_range = each_cidr.split("NetName: ")
                            except:
                                cidr_range = []
                            organization_count = cidr_range[1].count("Organization:")
                            if organization_count > 0: # if the word 'organization' exists in section, we parse out the organization
                                organization_all = ["a%d" % x for x in range(organization_count)]
                                try:
                                    organization_all = cidr_range[1].split("Organization:")
                                except:
                                    organization_all = []
            
                                try: # part of parsing out 'Organization' name
                                    regdate_count = organization_all[1].count("RegDate:")
                                    just_org_all = ["a%d" % x for x in range(regdate_count)]
                                    just_org_all = organization_all[1].split("RegDate:")
                                    organization_nospace = just_org_all[0].lstrip()
                                    organization_nospace = organization_nospace.rstrip()
                                    # Append the parsed 'Organization' name into the array
                                    organization_customer_name.append(organization_nospace)
                                    if cidr_range[0] != "":
                                        cidr_range_nospace = cidr_range[0].lstrip()
                                        cidr_range_nospace = cidr_range_nospace.rstrip()
                                        comma_count = cidr_range_nospace.count(",")
                                        eachof_cidr = ["a%d" % x for x in range(comma_count)]
                                        eachof_cidr = cidr_range_nospace.split(",")
                                        current_greatest_cidr = eachof_cidr[0]
                                        ip, current_greatest_subnet = current_greatest_cidr.split("/")
                                        # find the greatest cidr if there are several, e.g. 205.140.160.0/19, 205.140.160.0/20, 205.140.160.0/21, || 205.140.160.0/21 would be desired cidr
                                        for individ_cidr in eachof_cidr:
                                            individ_cidr = individ_cidr.lstrip()
                                            slash_count =  individ_cidr.count("/")
                                            each_subnet = ["a%d" % x for x in range(slash_count)]
                                            ip, each_subnet = individ_cidr.split("/")
                                            if each_subnet >= current_greatest_subnet:
                                                current_greatest_subnet = each_subnet
                                                current_greatest_final_cidr = individ_cidr
                                        # Append the parsed 'CIDR' into the array
                                        cidr_array.append(current_greatest_final_cidr)                    
                                except:
                                    print("bad format, no organization")
                            # if no organizations found in the section of this particular cidr, look for customer name
                            elif organization_count == 0: # if the word 'organization' DOESN'T exist in section, we parse out the 'Customer'
                                customer_count = cidr_range[1].count("Customer:")
                                customer_all = ["a%d" % x for x in range(customer_count)]
                                try:
                                    customer_all = cidr_range[1].split("Customer:")
                                except:
                                    customer_all = []
                                try: # part of parsing out 'Customer' name
                                    regdate_count = customer_all[1].count("RegDate:")
                                    just_customer_all = ["a%d" % x for x in range(regdate_count)]
                                    just_customer_all = customer_all[1].split("RegDate:")
                                    customer_nospace = just_customer_all[0].lstrip()
                                    customer_nospace = customer_nospace.rstrip()
                                    # Append the parsed 'Customer' name into the array
                                    organization_customer_name.append(customer_nospace)
                                    if cidr_range[0] != "":
                                        cidr_range_nospace = cidr_range[0].lstrip()
                                        cidr_range_nospace = cidr_range_nospace.rstrip()
                                        comma_count = cidr_range_nospace.count(",")
                                        eachof_cidr = ["a%d" % x for x in range(comma_count)]
                                        eachof_cidr = cidr_range_nospace.split(",")
                                        current_greatest_cidr = eachof_cidr[0]
                                        ip, current_greatest_subnet = current_greatest_cidr.split("/")
                                        # find the greatest cidr if there are several, e.g. 205.140.160.0/19, 205.140.160.0/20, 205.140.160.0/21, || 205.140.160.0/21 would be desired cidr
                                        for individ_cidr in eachof_cidr:
                                            individ_cidr = individ_cidr.lstrip()
                                            slash_count =  individ_cidr.count("/")
                                            each_subnet = ["a%d" % x for x in range(slash_count)]
                                            ip, each_subnet = individ_cidr.split("/")
                                            if each_subnet >= current_greatest_subnet:
                                                current_greatest_subnet = each_subnet
                                                current_greatest_final_cidr = individ_cidr
                                        # Append the parsed 'CIDR' into the array
                                        cidr_array.append(current_greatest_final_cidr)
                                except:
                                    print("bad format, no customer")

                            else:
                                print("Organization or Customer, Not Found")
                            
            except:
                # if whois returns a record without 'CIDR', or 'Organization'/'Customer', we recursively lookup a different mx record to get valid whois
                recursive_whois_counter+=1
                if recursive_whois_counter <= 15:
                    #print("Looking for valid whois records")
                    retrieve_MX(mx_subprocess, domain_to_pass_mx)
                else:
                    print("No ip to run whois")

        except:
            print("Error retrieving DMARC record")

    # get highest CIDR subnet, once found, take the corresponding 'Organization', 'Customer' and write out Domain, Email Provider. Email Provider is 'Organization' or 'Customer'
    def get_highest_cidr_info(domain_to_pass_mx):
        try:
            domain = domain_to_pass_mx
            index_of_greatest_cidr = 0
            organization_or_customer_name_write = ""
            if len(cidr_array) == 1 and len(organization_customer_name) == 1:
                try:
                    organization_customer_string = "".join((domain_to_pass_mx, ",", organization_customer_name[0], "\n"))
                    email_provider_output_txt.write(organization_customer_string)
                except:
                    print("no items")
            elif len(cidr_array) > 1 and len(organization_customer_name) > 1:
                current_cidr_greatest = cidr_array[0]
                try:
                    ip, current_greatest_subnet = current_cidr_greatest.split("/")
                except:
                    ip = ""
                    current_greatest_subnet = ""
                # find the greatest subnet. e.g. [192.222.222.222/20, 192.222.223.223/21] -> 21 higher, so we want 192.222.223.223/21, get corresponding Org, Cust
                # e.g. CIDR Array: [192.222.222.222/20, 192.222.223.223/21], EmailProvider Array: [Oracle Corporation (ORACLE-4), Proofpoint, Inc. (PROOF)]
                # So we want Email Provider: Proofpoint, Inc. (PROOF). We write out -> ||| Domain (Example.Org), (EmailProvider) Proofpoint, Inc. (PROOF) ||||
                for individ_cidr in cidr_array:
                    individ_cidr = individ_cidr.lstrip()
                    slash_count =  individ_cidr.count("/")
                    each_subnet = ["a%d" % x for x in range(slash_count)]
                    try:
                        ip, each_subnet = individ_cidr.split("/")
                    except:
                        ip = ""
                        each_subnet = ""
                    if each_subnet >= current_greatest_subnet:
                        current_greatest_subnet = each_subnet
                        current_cidr_greatest = individ_cidr
                        index_of_greatest_cidr  = cidr_array.index(individ_cidr)
                # try to write out Domain, Email provider to txt output file
                try:
                    organization_or_customer_name_write = organization_customer_name[index_of_greatest_cidr]
                    organization_customer_string = "".join((domain_to_pass_mx, ",", organization_or_customer_name_write, "\n"))
                    email_provider_output_txt.write(organization_customer_string)
                except:
                    print("bad format, out of bounds of array")
                    
            else:
                print("No items")
        except:
                print("Error getting CIDR info")    
                 
    # retrieve the mx records for a domain. Parse out the mx with the highest priority, to pass it to 'whois_execute_parse' function above
    def retrieve_MX(mx_subprocess, domain_to_pass_mx):
        try:
            global count_of_times_looped
            count_of_times_looped = 0
            mx_subprocess = mx_subprocess.rstrip()
            lowest_value_higest_priority = ""
            global subdomain
            subdomain = ""
            #run dig command on all lines in the text file , out is output of the collected mx or empty
            proc=subprocess.Popen(shlex.split(mx_subprocess),stdout=subprocess.PIPE)
            out,err=proc.communicate()
            # convert dmarc (in bytes) to a string
            byte_to_string_mx = str(out, 'utf-8')
            # check if mx exists, write it to output file
            if byte_to_string_mx != "":
                byte_to_string_mx_new = byte_to_string_mx.rstrip()
                mx_space_count = byte_to_string_mx_new.count("\n")
                each_mx = ["a%d" % x for x in range(mx_space_count)]
                try:
                    each_mx = byte_to_string_mx_new.split("\n")
                    first_priority = each_mx[0]
                    mxone, mxtwo, mxthree, mxfour, first_prior, mxsix = first_priority.split()
                    current_greatest_mx_priority = int(first_prior)
                    current_MX_to_use = ""
                    # Go through each MX, parse and output it
                    for mx in each_mx:
                        mx1, mx2, mx3, mx4, mx5, mx6 = mx.split()
                        mx6 = mx6[:-1]
                        if int(mx5) < current_greatest_mx_priority: # parse out mx with highest priority
                            current_greatest_mx_priority = int(mx5)
                            current_MX_to_use = mx
                        domain_plus_mx = "".join((domain_remove_newline,",",mx6,",",mx5,",",mx2,",",dt, "\n"))
                        if recursive_whois_counter == 0:
                            mx_output_txt.write(domain_plus_mx) # write out the mx records to output txt file
                    # Parse MX with the lowest priority value/number (Highest actual priority)
                    if current_MX_to_use == "":
                        try:
                            if recursive_whois_counter < len(each_mx):
                                whole_mx_before = each_mx[recursive_whois_counter]
                                whole_mx = whole_mx_before.split()
                                for i in whole_mx:
                                    try:
                                        subdomain = whole_mx[5] # this is mx's subdomain that has highest priority, lowest actual value
                                    except:
                                        print("No mx found")
                            
                            elif recursive_whois_counter == 0:
                                whole_mx_before = each_mx[0]
                                whole_mx = whole_mx_before.split()
                                for i in whole_mx:
                                    try:
                                        subdomain = whole_mx[5] # this is mx's subdomain that has highest priority, lowest actual value
                                    except:
                                        print("No mx found")
                        
                        except:
                            print("No mx record available") 
                    else:
                        try:
                            whole_mx = current_MX_to_use.split()
                            for i in whole_mx:
                                try:
                                    subdomain = whole_mx[5] # this is mx's subdomain that has highest priority
                                except:
                                    print("No mx found")
                        except:
                            print("No mx record available")
                
                except:
                    print("Couldn't Parse a subdomain for a highest priority, executing next record")

                Host_to_IP_NSLookup = ("nslookup -q=A ")
                nslookup_plus_subdomain = "".join((Host_to_IP_NSLookup, subdomain))
                if subdomain != "":
                    proc=subprocess.Popen(shlex.split(nslookup_plus_subdomain),stdout=subprocess.PIPE)
                    out,err=proc.communicate()
                    #convert ip (in bytes) to a string
                    byte_to_string_ip = str(out, 'utf-8')
                    match_word = "Non-authoritative answer"
                    match_word1 = "Can't find"
                    match_word2 = "server can't find"
                    if (match_word in byte_to_string_ip and not match_word1 in byte_to_string_ip and not match_word2 in byte_to_string_ip):
                        count_all_address = byte_to_string_ip.count("Address: ")
                        address_list = ["a%d" % x for x in range(count_all_address)]
                        # split list into seperate addressess for all addresses
                        try:
                            address_list = byte_to_string_ip.split("Address: ")
                        except:
                            address_list = []
                        for address in address_list:
                            if address_list.index(address) == count_all_address and count_all_address == 1:
                                address = address.rstrip()
                                whois_execute_parse(address, mx_subprocess, domain_to_pass_mx) # call whois function
                                count_of_times_looped += 1
                            elif address_list.index(address) == 1:
                                try:
                                    address, extra = address.split("Name:")
                                except:
                                    address = ""
                                    extra = ""
                                address = address.rstrip()
                                whois_execute_parse(address, mx_subprocess, domain_to_pass_mx) # call whois function
                                count_of_times_looped += 1
                    for i in range(1,2):
                        if count_of_times_looped == 1: # if no recursion
                            get_highest_cidr_info(domain_to_pass_mx) # get highest cidr for the domain to get its corresponding Organziation/Customer
                        elif count_of_times_looped > 1: # if recursion happens, counter is greater than 1, so we just print out recurision happened
                            print("recursion, avoiding multiple writes")
                
            else:
                domain_plus_no_record = "".join((domain_remove_newline, ",", "MX,","NoRecord,",dt,"\n"))
                mx_output_txt.write(domain_plus_no_record)
                organization_customer_string = "".join((domain_remove_newline, ",", "NoEmailProvider", "\n"))
                email_provider_output_txt.write(organization_customer_string)
        except:
            print("Error retreiving MX record")
    # retrieve domains TXT records
    def retrieve_TXT(txt_subprocess):
        try:
            #run dig command on all lines in the text file , out is output of the collected txt or empty
            proc=subprocess.Popen(shlex.split(txt_subprocess),stdout=subprocess.PIPE)
            out,err=proc.communicate()

            # convert dmarc (in bytes) to a string
            byte_to_string_txt = str(out, 'utf-8')

            # check if txt exists, write it to output file
            if byte_to_string_txt != "":
                byte_to_string_txt_new = byte_to_string_txt.rstrip()
                txt_space_count = byte_to_string_txt_new.count("\n")
                each_txt = ["a%d" % x for x in range(txt_space_count)]
                try:
                    each_txt = byte_to_string_txt_new.split("\n")
                except:
                    each_txt = []
                for txt in each_txt:
                    try:
                        txt_parts  = txt.split('"')
                    except:
                        txt_parts = []
                    for i in txt_parts:
                        if txt_parts.index(i) == 1:
                            if i[0:6] == "v=spf1":
                                domain_plus_txt = "".join((domain_remove_newline,",","SPF",",",i,",",dt, "\n"))
                                dmarc_output_txt.write(domain_plus_txt)
                            else:
                                domain_plus_txt = "".join((domain_remove_newline,",","TXT",",",i,",",dt, "\n"))
                                dmarc_output_txt.write(domain_plus_txt)
            else:
                domain_plus_no_record = "".join((domain_remove_newline, ",", "TXT,","NoRecord,",dt,"\n"))
                dmarc_output_txt.write(domain_plus_no_record)
        except:
            print("Error retrieving TXT record(s)")

    # if we can read an input char, then we continue execution    
    if dmarc_input_txt.read(1):
        dmarc_input_txt.seek(0)
    else: # no input, so no records to parse, write no records to output txt file
        dmarc_none_output_txt = open(path_out,'a+') 
        dmarc_none_output_txt.write("NO RECORDS")
        dmarc_none_output_txt.close()

    
    # read each line of the input file until EOF
    for a_domain in dmarc_input_txt:
        try:
            # remove newline for each domain
            domain_remove_newline = a_domain.rstrip()
            # test for command on specific NAMESERVER
            if ' ' in domain_remove_newline:
                try:
                    the_domain, NAME_SERVER = domain_remove_newline.split()
                except:
                    the_domain = ""
                    NAME_SERVER = ""
                # setup dig + domain command + NAMESERVER (Retrieve Dmarc)
                dig_cmd = "dig +short TXT _dmarc."
                dmarc_record_ns = "".join((dig_cmd,the_domain," ","@",NAME_SERVER))
                retrieve_dmarc(dmarc_record_ns)
                # setup dig +nocmd +noall +answer +ttlid mx domain.com (Retrieve MX)
                domain_to_pass_mx = the_domain.rstrip()
                dig_cmd_mx = "dig +nocmd +noall +answer +ttlid mx "
                mx_record_ns = "".join((dig_cmd_mx,the_domain))
                recursive_whois_counter = 0
                retrieve_MX(mx_record_ns, domain_to_pass_mx)
                # setup dig +nocmd +noall +answer +ttlid mx domain.com (Retrieve TXT)
                dig_cmd_txt = "dig +nocmd +noall +answer +ttlid txt "
                txt_record_ns = "".join((dig_cmd_txt,the_domain))
                retrieve_TXT(txt_record_ns)
            # No specific NAMESERVER
            else:
                # setup dig + domain command (Retrieve Dmarc)
                dig_cmd = "dig +short TXT _dmarc."
                dmarc_record = "".join((dig_cmd,a_domain))
                retrieve_dmarc(dmarc_record)
                # setup dig +nocmd +noall +answer +ttlid mx domain.com (Retrieve MX)
                domain_to_pass_mx = a_domain.rstrip()
                dig_cmd_mx = "dig +nocmd +noall +answer +ttlid mx "
                mx_record_ns = "".join((dig_cmd_mx,a_domain))
                recursive_whois_counter = 0
                retrieve_MX(mx_record_ns, domain_to_pass_mx)
                # setup dig +nocmd +noall +answer +ttlid mx domain.com (Retrieve TXT)
                dig_cmd_txt = "dig +nocmd +noall +answer +ttlid txt "
                txt_record_ns = "".join((dig_cmd_txt,a_domain))
                retrieve_TXT(txt_record_ns)
            domain_processed = a_domain.rstrip()
            print("Processed:",domain_processed)
        except:
            print("Couldn't process all of record, formatting error on:", domain_remove_newline)
    # close files
    dmarc_input_txt.close()
    dmarc_output_txt.close()
    mx_output_txt.close()
    email_provider_output_txt.close()
    
