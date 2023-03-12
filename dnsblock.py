#!/usr/bin/env python
#
#
# Pulls the curl DNS over HTTP Blocklist from github and creates JSON
# Suitable to import into Untangle Web Filter blocklist
# 
# Adapted from https://gist.github.com/kimbo/dd65d539970e3a28a10628f15398247b
#
import argparse
import re
import urllib.request
import json
import json

HTTPS_URL_RE = re.compile(r'https://'
                          r'(?P<hostname>[0-9a-zA-Z._~-]+)'
                          r'(?P<port>:[0-9]+)?'
                          r'(?P<path>[0-9a-zA-Z._~/-]+)?')

PROVIDER_RE = re.compile(r'(\[([^\]]+)\]\(([^)]+))\)|(.*)')

# URLs that are not Doh URLs
do_not_include = ['my.nextdns.io', 'blog.cloudflare.com', 'https://blog.cloudflare.com/welcome-hidden-resolver', 'https://my.nextdns.io/start']


def get_doh_providers():
    found_table = False
    with urllib.request.urlopen('https://raw.githubusercontent.com/wiki/curl/curl/DNS-over-HTTPS.md') as fp:
        for line in fp:
            line = line.decode()
            if line.startswith('|'):
                if not found_table:
                    found_table = True
                    continue
                cols = line.split('|')
                provider_col = cols[1].strip()
                website = None
                provider_name = None
                matches = PROVIDER_RE.findall(provider_col)
                if matches[0][3] != '':
                    provider_name = matches[0][3]
                if matches[0][1] != '':
                    provider_name = matches[0][1]
                if matches[0][2] != '':
                    website = matches[0][2]
                if provider_name is not None:
                    provider_name = re.sub(r'([^[]+)\s?(.*)', r'\1', provider_name)
                    while provider_name[-1] == ' ':
                        provider_name = provider_name[:-1]
                if len(cols) < 3:
                    continue
                url_col = cols[2]
                doh_url_matches = HTTPS_URL_RE.findall(url_col)
                if len(doh_url_matches) == 0:
                    continue
                else:
                    for doh_url in doh_url_matches:
                        if doh_url[0] in do_not_include:
                            continue
                        yield {
                            'name': provider_name,
                            'website': website,
                            'url': 'https://{}{}{}'.format(doh_url[0], ':{}'.format(doh_url[1]) if len(doh_url[1]) != 0 else '', doh_url[2]),
                            'hostname': doh_url[0],
                            'port': doh_url[1] if len(doh_url[1]) != 0 else '443',
                            'path': doh_url[2],
                        }
            if found_table and line.startswith('#'):
                break
    return

def main():
    retval=[]
    idc = 1
    # example: ./scripts/scrape_doh_providers.py '"{} - {}".format(o["url"], o["name"])'
    parser = argparse.ArgumentParser(description='A script to parse DoH provider URLs from cURL\'s wiki page!')
    parser.add_argument('format', help='Format of output. Example: \'*(o["url"],o["name"])\'', default='o["hostname"]',
                        nargs='?')
    args = parser.parse_args()
    for o in get_doh_providers():
        r = {}
        r["string"] = o["hostname"]
        r["blocked"] =  True
        r["flagged"] =  True
        r["javaClass"] = "com.untangle.uvm.app.GenericRule"
        r["name"] = None
        r["category"] =  None
        r["enabled"] =  None
        r["readOnly"] =  None
        r["id"] = idc
        r["description"] = "autoimport"
        retval.append(r)
        idc += 1

    print(json.dumps(retval))


if __name__ == '__main__':
    main()
