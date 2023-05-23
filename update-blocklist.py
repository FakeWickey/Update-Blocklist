#! /usr/bin/env python3

import configparser, sys, re, subprocess

# read config and decide wether we are in standalone or database-attached mode
config = configparser.ConfigParser()
config.read('config.ini') # Reads config file

advanced_mode = config.getboolean('advanced', 'enable_advanced_mode')

# trying to import needed modules
try:
    if advanced_mode:
        import requests
        from sqlalchemy import create_engine
    else:
        import requests
except ImportError:
    print(f'Please install modules "requests" and "sqlalchemy", as they are needed by this script.')
    sys.exit(1)

def create_database_connection():
    db_params = config['database']
    db_uri = f"mysql://{db_params['username']}:{db_params['password']}@{db_params['host']}:{db_params['port']}/{db_params['database_name']}"

    engine = create_engine(db_uri)
    return engine

def lines_to_list(lines):
    lines = lines.split('\n')
    list = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        list.append(line)
    return list

if advanced_mode:
    # Creating a low level connection to the database to retrieve adlists data (specifically the type and url data)
    engine = create_database_connection()

    result = engine.execute("SELECT type,url FROM adlists") # writes to a new database table
    adlists_data = result.fetchall()

    # formatting into list of dicts
    list_of_adlists = []
    for mysql_domain in adlists_data:
        mysql_domain = dict(mysql_domain)
        list_of_adlists.append(mysql_domain)
else:
    list_of_adlists = []

    # helper-function
    def add_type_to_list_of_adlists(list, type):
        list_with_dicts = []
        for url in list:
            dictionary = {'type': type, 'url': url}
            list_with_dicts.append(dictionary)
        return list_with_dicts

    # hosts-formatted adlists
    hosts_list = lines_to_list(config.get('adlists', 'host_formatted'))
    hosts_dicts = add_type_to_list_of_adlists(hosts_list, 'hosts')

    # adblock-formatted adlists
    adblock_list = lines_to_list(config.get('adlists', 'adblock_formatted'))
    adblock_dicts = add_type_to_list_of_adlists(adblock_list, 'adblock')

    list_of_adlists = hosts_dicts + adblock_dicts

hosts_file_path = config.get('general', 'hosts_file_path')
if advanced_mode:
    # Get script_enabled value from database
    result = engine.execute('SELECT script_enabled FROM general_settings')
    general_settings_data = result.fetchone()

    script_enabled_value = dict(general_settings_data)['script_enabled']
else:
    # Get script_enabled value from config.ini
    script_enabled = config.get('general', 'script_enabled')
    if script_enabled == True:
        script_enabled_value = 1
    else:
        script_enabled_value = 0

# empty hosts_file if script is not enabled,
# resulting in no domain being blocked by dnsmasqd
if script_enabled_value == 0:
    file_pointer = open(hosts_file_path, 'w')

    file_pointer.writelines('')
    file_pointer.close()

def download(url):
    url_response = requests.get(url, timeout = 20)
    return url_response.text

# parse hosts-formatted adlists, hosts-formatted adlists are line-based. hosts-formatted adlists can contain comments
# return a list of domains
def parse_hosts(url_body):
    lines = url_body.split("\n")

    # initialize 'domains' list, so that we can return the list of domains at the end of the function
    domains = []

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

        # Regex for checking if the line is formatted correctly; group 1 includes the domain
        hosts_regex = r"^.*?[\s\t]+(.*?)([\s\t]|#|$)"
        hosts_result = re.finditer(hosts_regex, line)
 
        # hosts_domain is initialized as false; if regex found something, and its not empty; append the domain.
        # if regex didn't match, or the capturing group 1 doesn't contain anything; delete the line and don't append
        hosts_domain = False
        for result in hosts_result:
            hosts_domain = result.group(1)

        key += 1
        if hosts_domain:
            domains.append(hosts_domain)
    return domains

# parse adblock-formatted adlists, adblock-formatted adlists are more complicated than hosts-formatted adlists with their syntax.
# see https://adguard.com/kb/de/general/ad-filtering/create-own-filters/ for the syntax.
# return a list of domains
def parse_adblock(url_body):
    # The reason that it is splitted into lines, is so each line can be parsed individually. The formatting is line based
    lines = url_body.split("\n")

    # initialize 'domains' list, so that we can return the list of domains at the end of the function
    domains = []
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


        # filter options parsing
        # filter options fine control which resource the rule applies to (in a webpage loading context; when loading a website some ressources are e.g. thirdparty and so on)
        if '$' in line:
            severed_line = line.split('$')
            filter_options = severed_line[1]

            # gets each filter option as a list item
            list_of_filter_options = filter_options.split(',')

            # these options must apply to the ressource in order for us to block it. (if the adblock-format line doesn't block resources from that domain broadly enough (e.g. when only
            # stylesheets from that domain are supposed to be blocked we don't want to block because we can only block everything for that domain in every context))
            # we set them to true because we assume that they are true by default and only get modified by filter options
            needed_options = {'script': True, 'image': True, 'stylesheet': True, 'object': True, 'subdocument': True, 'xmlhttprequest': True, 'websocket': True, 'webrtc': True, 'popup': True}

            # defines options that - when occuring - mean a ressource shouldn't be blocked in all cases
            bad_options = ['domain', 'third-party']

            # Loops trough all filter_options to look at each one separately
            break_out_flag = False
            for filter_option in list_of_filter_options:
                tilda_existence = False

                # Separate '~' from type option name, so that we can parse the type option
                # (remember if a tilda was found for either enabling or disabling the type option)
                if "~" in filter_option:
                    tilda_existence = True
                    filter_option = filter_option.replace("~", "")

                # get only the type option name and not the value
                splitted_filter_option = filter_option.split("=")

                # if a bad option appears don't block the domain
                if splitted_filter_option[0] in bad_options:
                    del lines[key]
                    break_out_flag = True
                    break

                # set all filter options accordingly, if 'all' option appears
                if filter_option == 'all':
                    for option in needed_options:
                        needed_options[option] = not(tilda_existence)

                # update dictionary of needed_options according to the filter_options of the resource
                if filter_option in needed_options.keys():
                    needed_options.update({filter_option: not(tilda_existence)})

            # helper to break out twice (like 'continue 2' would if that would exist in python) 
            if break_out_flag:
                continue

            # checks if all the needed_options are set to true
            for value in needed_options.values():
                if not value:
                    del lines[key]
                    continue

        key +=1
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

def parse(url_body, format):

    if format == 'hosts':
        return parse_hosts(url_body)
    elif format == 'adblock':
        return parse_adblock(url_body)

    print('THIS SHOULD NEVER HAPPEN. IT MEANS THERE IS AN ERROR IN THE SCRIPT')
    sys.exit(0)

# initiates final_list_of_domains list for later use
final_list_of_domains = []

# main loop
# iterates over adlists, downloads and triggers parsing. at the end all domains are combined
for adlist in list_of_adlists:
    url_body = download(adlist['url'])
    list_of_domains = parse(url_body, adlist['type'])

    final_list_of_domains = final_list_of_domains + list_of_domains

# turns final_list_of_domains from dictionary into a list
final_list_of_domains = list(dict.fromkeys(final_list_of_domains))

# --> file pointers, file write
file_pointer = open(hosts_file_path, 'w')

ip_address_overwrite = config.get('general', 'ip_address_overwrite')
for domain in final_list_of_domains:
    hosts_pair = f'{ip_address_overwrite}   {domain}\n'
    file_pointer.writelines(hosts_pair)

file_pointer.close()

# only run "systemctl reload" if not running on windows
# assuming we must be on linux then
if not sys.platform.startswith('win'):
    subprocess.run("systemctl reload dnsmasq.service", shell=True)
