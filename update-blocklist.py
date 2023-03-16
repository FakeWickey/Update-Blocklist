#! /usr/bin/env python3

# The approach is to download adlists, and find out what's usable for blocking, then filter out the domains to a textfile/configuration file. Splitting into lines because of line based formatting

import requests, re, subprocess

list_of_adlists = [
    {
        'url': 'https://someonewhocares.org/hosts/hosts',
        'format': 'hosts'
    },
    {
        'url': 'https://malware-filter.pages.dev/urlhaus-filter-online.txt',
        'format': 'adblock'
    },
    {
        'url': 'https://easylist.to/easylist/easyprivacy.txt',
        'format': 'adblock'
    }
]


def download(url):
    url_response = requests.get(url, timeout = 20)
    # The reason that it is splitted into lines, is so each line can be parsed individually. The formatting is line based
    list_of_lines = url_response.text.split("\n")
    return list_of_lines


def parse(lines, format):
    # domains is initialized because it will be used later to return
    domains = []

    if format == 'hosts':
        key = 0
        while key < len(lines):
            line = lines[key]

            # Checks if line starts with a '#'; excludes line, because its a comment
            if line.startswith('#'):
                del lines[key]
                continue

            # Checks if the line is empty; excludes line, because it doesn't contain anything
            if not line:
                del lines[key]
                continue

            # Checks for empty spaces in a line; same as the above, but a workaround for lines with nothing but spaces or tabulators in them
            if not line.strip():
                del lines[key]
                continue
            
            # Checks if the lines are correctly formatted; group 1 includes a domain
            hosts_regex = r"^.*?[\s\t]+(.*?)([\s\t]|#|$)"
            hosts_result = re.finditer(hosts_regex, line)

            # hosts_domain is initialized as false; if regex found something, and its not empty; append the domain.
            # if regex didn't match, or the capturing group 1 didn't match or evaluates to False; delete the line and doesn't append
            hosts_domain = False
            for result in hosts_result:
                hosts_domain = result.group(1)

            key += 1
            if hosts_domain:
                domains.append(hosts_domain)

    elif format == 'adblock':
        # initialized for later collection of exclude_rule lines
        excluderules_lines = []

        key = 0
        while key < len(lines):
            line = lines[key]

            # Save exclude rule lines in a different variable
            if line.startswith('@@'):
                excluderules_lines.append(line)
                del lines[key]
                continue

            # Only include lines starting with '||' cause that means 'any protocol'
            if not line.startswith('||'):
                del lines[key]
                continue

            # Exclude element hiding rules
            if '##' in line:
                del lines[key]
                continue

            # Exclude lines with pipes at the end
            if line.endswith('|'):
                del lines[key]
                continue

            # Checks if the lines are correctly formatted; group 1 includes a domain
            adblock_regex = r"^\|\|(([\w]+\.)[\w]+)[^\w_.,%-]([^\w_.,%-]|$)"
            adblock_domain = re.finditer(adblock_regex, line)

            # domain_name is initialized as false; if regex found something, and its not empty; append the domain.
            # if regex didn't match, or the capturing group 1 didn't match or evaluates to False; delete the line and doesn't append
            domain_name = False

            for result in adblock_domain:
                domain_name = result.group(1)
                
            if not domain_name:
                del lines[key]
                continue
            

            # filter option parsing
            # filter options fine control to which resource the rule applies to
            if '$' in line:
                severed_line = line.split('$')
                filter_options = severed_line[1]

                # gets each filter option into a list
                list_of_filter_options = filter_options.split(',')

                # these options define which elements of a webpage will be blocked; they are given a value of True because the assumption is that they are enabled by default
                # they are initialized because the set of type options or only the the type options we later need t.... domain blocking rule gets applied broadly enough to block the domain
                needed_options = {'script': True, 'image': True, 'stylesheet': True, 'object': True, 'subdocument': True, 'xmlhttprequest': True, 'websocket': True, 'webrtc': True, 'popup': True}

                # are type options which affect the sites in ways which are unfavorable
                bad_options = ['domain', 'third-party']

                # Loops trough the filter_options to look at each filter_option
                break_out_flag = False
                for filter_option in list_of_filter_options:
                    tilda_existence = False

                    # Removes '~' from type options, because it creates unneccessary difficulties
                    if "~" in filter_option:
                        tilda_existence = True
                        filter_option = filter_option.replace("~", "")

                    # Splits the type options, so it can be parsed trough more easily
                    splitted_filter_option = filter_option.split("=")
                    
                    # deletes line if corresponds with a bad_option, because bad_options are bad
                    if splitted_filter_option[0] in bad_options:
                        del lines[key]
                        break_out_flag = True
                        break


                    # if the type option is 'all', removes the '~', because it would block all type options
                    # updates each needed_option to either True of False whether or not they have a ~ or not
                    if filter_option == "all":
                        for option in needed_options:
                            needed_options[option] = not(tilda_existence)

                    # Set the needed_option according to the filter_option
                    if filter_option in needed_options.keys():
                        needed_options.update({filter_option: not(tilda_existence)})


                if break_out_flag:
                    continue
                    
                # checks if all the needed_options are set to true
                for value in needed_options.values():
                    if not value:
                        del lines[key]
                        continue

            key += 1
            domains.append(domain_name)

        # Checks if the lines are correctly formatted; group 2 includes a domain
        excluderules_regex = r"^@@\|{1,2}(https?://)?(.*?)([^\w_.,%-]|$)"
        
        # Regex compares each exclude_rule line for 
        for exclude_rule in excluderules_lines:
            regex_result = re.finditer(excluderules_regex, exclude_rule)
            domain_name = False

            # Adds the domain to domain_name variable
            for result in regex_result:
                domain_name = result.group(2)

            # Removes a domain that appears in an exclude rule
            if domain_name:
                if domain_name in domains:
                    domains.remove(domain_name)
    return domains

# initiates final_list_of_domains list for later use
final_list_of_domains = []

# iterates trough each adlist once; calls the download function and parse function and creates a list called final_list_of_domains where it stores the individual domains
for adlist in list_of_adlists:
    list_of_lines = download(adlist['url'])
    list_of_domains = parse(list_of_lines, adlist['format'])

    final_list_of_domains = final_list_of_domains + list_of_domains

# turns final_list_of_domains into a list from a dictionary
final_list_of_domains = list(dict.fromkeys(final_list_of_domains))


# --> File pointers, File Write
file_pointer = open('/etc/hosts.adserver', 'w')

for domain in final_list_of_domains:
    ip_address = f'127.0.0.1   {domain}\n'
    file_pointer.writelines(ip_address)

file_pointer.close()

subprocess.run("systemctl reload dnsmasq.service", shell=True)